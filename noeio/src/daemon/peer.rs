use crate::tunnel::session::{
    Datagram, SessionState, TunnelSession, UdpTunnelSession, WireGuardTunnelSession,
};
use crate::tunnel::wireguard::derive_tunnel_keys;
use noeio_common::host_info::{NatType, PeerId, PeerInfo};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How much lower a challenger's measured RTT must be to displace the
/// currently selected session, in percent. This is the debounce for path
/// selection: jitter between near-equal paths must not flap the route, so
/// only a clear win (RTT at least this much below the incumbent's) switches.
const RTT_SWITCH_IMPROVEMENT_PERCENT: u128 = 20;

/// How often the per-peer selector task re-evaluates the direct-path pick.
/// Kept well under the session ping interval so a freshly `Connected` (or
/// freshly dead) path is acted on promptly; the switch debounce is
/// [`RTT_SWITCH_IMPROVEMENT_PERCENT`], not this tick.
const SESSION_SELECT_INTERVAL: Duration = Duration::from_secs(2);

/// One candidate direct path to the peer: the address we punch to and the
/// session that maintains it (hole punch, ping/pong liveness, RTT probe).
pub struct PeerSession {
    /// Target address this session punches to and pings.
    pub addr: SocketAddr,
    /// The session itself. Only maintains reachability; business traffic goes
    /// over the outer UDP socket, not through it.
    pub session: Arc<Box<dyn TunnelSession>>,
    /// Inbound side: the global reader pushes this path's signalling datagrams
    /// onto this sender, and the session's `dispatch` task drains them.
    pub inbound_tx: mpsc::Sender<Datagram>,
}

/// Local runtime view of a peer.
///
/// Wraps the broadcast [`PeerInfo`] identity learned via `SyncRoute`.
///
/// A peer is a single shared instance behind `Arc` (see [`Self::new`]) — it is
/// deliberately not `Clone`, so there is exactly one session set, one selection
/// cell, and one selector task per peer, and no copy can go stale. Fields that
/// `SyncRoute` refreshes ([`Self::info`], [`Self::local_peer_id`],
/// [`Self::codec`]) use interior mutability so [`Self::update_info`] works
/// through `&self`.
pub struct Peer {
    /// Broadcast identity (peer_id / virtual IP / network). Behind a lock
    /// because a newer `SyncRoute` can rewrite it; read it via [`Self::info`].
    info: RwLock<PeerInfo>,
    /// Our own id in this peer's network, learned from the `SyncRoute` header.
    /// Stamped into the Seq/Ack/TunnelPing/TunnelPong packets this peer's
    /// sessions emit so the remote can resolve *us* (the sender) in its
    /// router — signalling packets carry the sender's id, unlike Forward which
    /// carries the receiver's. A `PeerId` is a `u32`, so an `AtomicU32` gives
    /// lock-free interior mutability; read it via [`Self::local_peer_id`].
    local_peer_id: AtomicU32,
    /// Shared outer UDP socket, used to open direct tunnel sessions to this
    /// peer on demand (e.g. after a `Timeout` session needs re-establishing).
    pub socket: Arc<UdpSocket>,
    /// Direct tunnel sessions to this peer, one per candidate address (see
    /// [`Self::candidate_addrs`]). Kept per-address so paths can be compared
    /// by RTT; [`Self::select_session`] picks which one serves the traffic.
    sessions: RwLock<Vec<PeerSession>>,
    /// Address of the session currently selected to carry direct traffic.
    /// Written only by [`Self::select_session`] (the selector task), read by
    /// [`Self::address`].
    selected: Mutex<Option<SocketAddr>>,
    /// Data-plane codec for traffic with this peer: encrypts outbound IP
    /// packets and decrypts inbound `Delivery` payloads. Sans-IO — the daemon
    /// owns the socket and the nic writer and executes what the codec's
    /// [`TunnOutput`](crate::tunnel::session::TunnOutput) instructs. Behind a
    /// lock because a key-changing `SyncRoute` rebuilds it; read it via
    /// [`Self::codec`].
    codec: RwLock<Arc<dyn TunnelSession>>,
}

/// Build the WireGuard codec for `info`, keyed by the deterministic pairwise
/// derivation. The peer's id doubles as boringtun's session index (it only
/// disambiguates our local session ids; boringtun keeps its low 24 bits).
fn build_codec(info: &PeerInfo, local_peer_id: PeerId) -> Arc<dyn TunnelSession> {
    let (secret, peer_public) = derive_tunnel_keys(local_peer_id, info.peer_id, info.network_id);
    Arc::new(WireGuardTunnelSession::new(secret, peer_public, info.peer_id))
}

impl Peer {
    /// Create a peer from its broadcast identity and spawn its selector task.
    ///
    /// A [`UdpTunnelSession`] is eagerly opened toward every candidate address
    /// (reported LAN addresses, plus the STUN address unless the peer is
    /// behind a symmetric NAT — see [`Self::candidate_addrs`]); a peer with no
    /// candidates starts with no direct session and is reached via the relay.
    /// `local_peer_id` is our own id in this peer's network (learned from the
    /// `SyncRoute` header). It is stamped into the Seq/Ack/TunnelPing/TunnelPong
    /// packets the sessions emit so the remote can resolve *us* in its router —
    /// signalling packets carry the sender's id, unlike Forward which carries
    /// the receiver's.
    ///
    /// Returns `Arc<Self>`: the peer is a shared singleton (the router hands
    /// out `Arc` clones), and the selector task tracks it through a `Weak` of
    /// this same allocation.
    pub fn new(info: PeerInfo, socket: Arc<UdpSocket>, local_peer_id: PeerId) -> Arc<Self> {
        let codec = build_codec(&info, local_peer_id);
        let peer = Arc::new(Self {
            info: RwLock::new(info),
            local_peer_id: AtomicU32::new(local_peer_id),
            socket,
            sessions: RwLock::new(Vec::new()),
            selected: Mutex::new(None),
            codec: RwLock::new(codec),
        });
        Self::spawn_selector(Arc::downgrade(&peer));
        peer.try_create_tunnel(false);
        peer
    }

    /// Spawn this peer's background selector task: a loop that periodically
    /// recomputes the direct-path pick via [`Self::select_session`].
    ///
    /// The task holds only a `Weak` reference, so it never keeps the peer
    /// alive; once the last `Arc` is dropped (the router entry is removed or
    /// replaced) the upgrade fails and the loop exits — at most one tick late.
    fn spawn_selector(peer: Weak<Peer>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SESSION_SELECT_INTERVAL).await;
                let Some(peer) = peer.upgrade() else {
                    break;
                };
                peer.select_session();
            }
        });
    }

    /// Snapshot of the broadcast identity. `PeerInfo` is small; callers get a
    /// consistent copy rather than holding the lock.
    pub fn info(&self) -> PeerInfo {
        self.info.read().unwrap().clone()
    }

    /// Our own id in this peer's network. See the field docs.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id.load(Ordering::Acquire)
    }

    /// The current data-plane codec. Cloning the `Arc` out means a concurrent
    /// key-changing `SyncRoute` can't invalidate the handle mid-use.
    pub fn codec(&self) -> Arc<dyn TunnelSession> {
        self.codec.read().unwrap().clone()
    }

    /// Candidate addresses for direct paths to this peer: the LAN addresses
    /// it reported plus its STUN-observed public address, deduplicated. Each
    /// candidate gets its own session and a seat in the RTT-based selection.
    ///
    /// The symmetric-NAT rule only excludes the STUN path — hole punching
    /// through a symmetric NAT doesn't work, but a LAN address is reachable
    /// regardless of the peer's NAT type. Empty when no path is known
    /// (relay-only).
    fn candidate_addrs(&self) -> Vec<SocketAddr> {
        let info = self.info();
        let nat_addr = (info.nat_type != NatType::Symmetric)
            .then_some(info.nat_addr)
            .flatten();
        let mut candidates = Vec::new();
        for addr in info.local_addrs.into_iter().chain(nat_addr) {
            // Dedup: a peer with a public interface can report the same
            // address as both LAN and STUN.
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }
        candidates
    }

    /// Reconcile the session set against [`Self::candidate_addrs`]. Does
    /// nothing (and never errors) when no work is needed:
    ///
    /// - sessions whose target is no longer a candidate (e.g. a stale
    ///   `nat_addr`) are dropped, which aborts their background tasks;
    /// - with `force == false`: a live session (`Connecting`/`Connected`) is
    ///   left as-is, and a fresh [`UdpTunnelSession`] is opened only for a
    ///   candidate with no session or a `Timeout` one;
    /// - with `force == true`: session state is ignored and every candidate
    ///   gets a fresh session replacing any existing one.
    pub fn try_create_tunnel(&self, force: bool) {
        let candidates = self.candidate_addrs();
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|s| candidates.contains(&s.addr));

        for addr in candidates {
            let usable = !force
                && sessions
                    .iter()
                    .any(|s| s.addr == addr && s.session.state() != SessionState::Timeout);
            if usable {
                continue;
            }
            self.open_session(&mut sessions, addr);
        }
    }

    /// Open a fresh [`UdpTunnelSession`] toward `addr` and store it in
    /// `sessions`, replacing any existing entry for that address. Dropping the
    /// replaced entry aborts its background tasks (if nothing else is holding
    /// it).
    ///
    /// Unconditional — callers gate on state via [`Self::try_create_tunnel`],
    /// which also owns the write lock this borrows.
    fn open_session(&self, sessions: &mut Vec<PeerSession>, addr: SocketAddr) {
        // `inbound_tx` is how the global reader feeds this path's signalling
        // datagrams into the session; the demux path pushes onto it so the
        // session's `dispatch` task can make progress.
        // Stamp our own id (not the target's): the remote resolves the sender of
        // a signalling packet by looking `local_peer_id` up in its router.
        let (session, inbound_tx) =
            UdpTunnelSession::connect(self.socket.clone(), addr, &self.local_peer_id());
        let entry = PeerSession {
            addr,
            session: Arc::new(Box::new(session)),
            inbound_tx,
        };
        match sessions.iter_mut().find(|s| s.addr == addr) {
            Some(slot) => *slot = entry,
            None => sessions.push(entry),
        }
    }

    /// The address to reach this peer directly, if a direct path is currently
    /// usable: the session the background selector picked (lowest RTT with
    /// debounce, see [`Self::select_session`]), provided it is still
    /// `Connected`. Otherwise `None`, meaning the caller should fall back to
    /// the relay.
    ///
    /// Deliberately does no selection work of its own — this sits on the send
    /// path, so it only reads the cached pick plus one atomic state load.
    pub fn address(&self) -> Option<SocketAddr> {
        let selected = (*self.selected.lock().unwrap())?;
        let sessions = self.sessions.read().unwrap();
        let entry = sessions.iter().find(|s| s.addr == selected)?;
        (entry.session.state() == SessionState::Connected).then_some(selected)
    }

    /// Re-evaluate which session should carry direct traffic and cache the
    /// pick for [`Self::address`] to read.
    ///
    /// Runs from this peer's selector task (see [`Self::spawn_selector`]),
    /// never from the send path. Among `Connected` sessions the lowest
    /// measured RTT wins, with debounce: an incumbent is only displaced by a
    /// challenger whose RTT is at least [`RTT_SWITCH_IMPROVEMENT_PERCENT`]
    /// lower, so jitter between near-equal paths doesn't flap the route. An
    /// incumbent that is no longer `Connected` is failed over immediately —
    /// debounce protects a healthy pick, not a dead one.
    fn select_session(&self) {
        let connected: Vec<(SocketAddr, Option<Duration>)> = self
            .sessions
            .read()
            .unwrap()
            .iter()
            .filter(|s| s.session.state() == SessionState::Connected)
            .map(|s| (s.addr, s.session.rtt()))
            .collect();

        let mut selected = self.selected.lock().unwrap();
        // The incumbent, if it's still among the connected sessions.
        let current =
            selected.and_then(|addr| connected.iter().find(|(a, _)| *a == addr).copied());
        // The challenger: lowest measured RTT; unmeasured sessions rank last.
        let best = connected
            .iter()
            .copied()
            .min_by_key(|(_, rtt)| rtt.unwrap_or(Duration::MAX));

        let next = match (current, best) {
            // No connected session at all.
            (_, None) => None,
            // No live incumbent: take the best immediately, measured or not.
            (None, Some((addr, _))) => Some(addr),
            (Some((cur_addr, cur_rtt)), Some((best_addr, best_rtt))) => {
                let improved = match (cur_rtt, best_rtt) {
                    (Some(cur), Some(best)) => {
                        best.as_millis() * 100
                            < cur.as_millis() * (100 - RTT_SWITCH_IMPROVEMENT_PERCENT)
                    }
                    // A measured challenger displaces an unmeasured incumbent…
                    (None, Some(_)) => true,
                    // …but an unmeasured challenger never displaces the pick.
                    (_, None) => false,
                };
                if best_addr != cur_addr && improved {
                    Some(best_addr)
                } else {
                    Some(cur_addr)
                }
            }
        };

        if next != *selected {
            tracing::debug!(
                peer_id = self.info().peer_id,
                previous = ?*selected,
                new = ?next,
                "direct-path session selection changed"
            );
        }
        *selected = next;
    }

    /// Feed an inbound signalling datagram to this peer's tunnel sessions.
    ///
    /// The global reader calls this after demuxing a datagram to this peer.
    /// Each session talks to one target address, so the datagram is routed to
    /// the session whose address matches `src`; a datagram from an unknown
    /// source (e.g. the peer answering a punch from a different port) is fanned
    /// out to every session, each of which validates nonces/timestamps itself.
    /// Returns `false` when nothing accepted it (no sessions, e.g. a
    /// symmetric-NAT peer, or all inbound channels closed); `true` when the
    /// datagram was queued to at least one session.
    pub async fn inbound(&self, payload: Vec<u8>, src: SocketAddr) -> bool {
        // Clone the senders out and drop the lock before awaiting: the guard
        // isn't `Send`, and blocking the lock across an await would stall
        // writers (`try_create_tunnel`).
        let txs: Vec<mpsc::Sender<Datagram>> = {
            let sessions = self.sessions.read().unwrap();
            match sessions.iter().find(|s| s.addr == src) {
                Some(entry) => vec![entry.inbound_tx.clone()],
                None => sessions.iter().map(|s| s.inbound_tx.clone()).collect(),
            }
        };
        let mut delivered = false;
        for tx in txs {
            delivered |= tx.send((payload.clone(), src)).await.is_ok();
        }
        delivered
    }

    /// Refresh the broadcast identity from a newer `SyncRoute`.
    ///
    /// If the peer's `network_id` or `nat_type` changed, the previous tunnel
    /// sessions are no longer valid for the new identity, so a fresh set is
    /// forced. Otherwise the session set is still reconciled (`force == false`)
    /// so a changed or newly learned `nat_addr` gets its session opened and
    /// stale-address sessions are dropped.
    pub fn update_info(&self, info: PeerInfo, local_peer_id: PeerId) {
        let (identity_changed, keys_changed) = {
            let mut current = self.info.write().unwrap();
            let identity_changed = current.network_id != info.network_id
                || current.nat_type != info.nat_type;
            // The codec's keys are derived from (network, peer id, our id); if
            // any of them changed, the old tunnel can no longer decrypt this
            // peer.
            let keys_changed = current.network_id != info.network_id
                || current.peer_id != info.peer_id
                || self.local_peer_id() != local_peer_id;
            *current = info;
            (identity_changed, keys_changed)
        };
        // Refresh our own id too: a re-addressed SyncRoute may carry a new one,
        // and a rebuilt session must stamp the current value.
        self.local_peer_id.store(local_peer_id, Ordering::Release);
        if keys_changed {
            *self.codec.write().unwrap() = build_codec(&self.info(), local_peer_id);
        }
        self.try_create_tunnel(identity_changed);
    }
}

#[cfg(test)]
mod select_session_tests {
    use super::*;

    /// A session stub with fixed state and RTT, standing in for a
    /// [`UdpTunnelSession`] whose probes produced those values.
    struct MockSession {
        state: SessionState,
        rtt: Option<Duration>,
    }

    impl TunnelSession for MockSession {
        fn state(&self) -> SessionState {
            self.state
        }

        fn rtt(&self) -> Option<Duration> {
            self.rtt
        }
    }

    fn entry(addr: &str, state: SessionState, rtt_ms: Option<u64>) -> PeerSession {
        let (inbound_tx, _) = mpsc::channel(1);
        PeerSession {
            addr: addr.parse().unwrap(),
            session: Arc::new(Box::new(MockSession {
                state,
                rtt: rtt_ms.map(Duration::from_millis),
            })),
            inbound_tx,
        }
    }

    /// A peer with the given session set and no background tasks — selection
    /// is driven by calling `select_session` directly.
    async fn test_peer(sessions: Vec<PeerSession>) -> Peer {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let info = PeerInfo::new(
            1,
            "10.64.0.2".parse().unwrap(),
            "00000000-0000-0000-0000-000000000000",
        )
        .unwrap();
        Peer {
            info: RwLock::new(info),
            local_peer_id: AtomicU32::new(7),
            socket,
            sessions: RwLock::new(sessions),
            selected: Mutex::new(None),
            codec: RwLock::new(Arc::new(MockSession {
                state: SessionState::Connecting,
                rtt: None,
            })),
        }
    }

    fn selected(peer: &Peer) -> Option<SocketAddr> {
        *peer.selected.lock().unwrap()
    }

    fn set_selected(peer: &Peer, addr: &str) {
        *peer.selected.lock().unwrap() = Some(addr.parse().unwrap());
    }

    const A: &str = "192.0.2.1:1000";
    const B: &str = "192.0.2.2:2000";

    #[tokio::test]
    async fn picks_lowest_rtt_when_no_incumbent() {
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, Some(100)),
            entry(B, SessionState::Connected, Some(50)),
        ])
        .await;
        peer.select_session();
        assert_eq!(selected(&peer), Some(B.parse().unwrap()));
    }

    #[tokio::test]
    async fn picks_unmeasured_session_when_it_is_the_only_one() {
        // A freshly connected path with no RTT sample yet must still be
        // usable — the pre-multipath behaviour of "Connected means routable".
        let peer = test_peer(vec![entry(A, SessionState::Connected, None)]).await;
        peer.select_session();
        assert_eq!(selected(&peer), Some(A.parse().unwrap()));
    }

    #[tokio::test]
    async fn debounce_keeps_incumbent_below_threshold() {
        // B is 19% faster: within the 20% debounce window, so no switch.
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, Some(100)),
            entry(B, SessionState::Connected, Some(81)),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(A.parse().unwrap()));
    }

    #[tokio::test]
    async fn debounce_keeps_incumbent_at_exact_threshold() {
        // Exactly 20% lower is not a *strictly* clear win; no switch.
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, Some(100)),
            entry(B, SessionState::Connected, Some(80)),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(A.parse().unwrap()));
    }

    #[tokio::test]
    async fn switches_on_clear_improvement() {
        // B is 21% faster: past the debounce threshold, switch.
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, Some(100)),
            entry(B, SessionState::Connected, Some(79)),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(B.parse().unwrap()));
    }

    #[tokio::test]
    async fn fails_over_immediately_when_incumbent_dies() {
        // The incumbent is no longer Connected: debounce must not apply, even
        // though the challenger's RTT is far worse than the incumbent's was.
        let peer = test_peer(vec![
            entry(A, SessionState::Timeout, Some(10)),
            entry(B, SessionState::Connected, Some(500)),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(B.parse().unwrap()));
    }

    #[tokio::test]
    async fn clears_selection_when_nothing_is_connected() {
        let peer = test_peer(vec![
            entry(A, SessionState::Timeout, None),
            entry(B, SessionState::Connecting, None),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), None);
    }

    #[tokio::test]
    async fn unmeasured_challenger_never_displaces_measured_incumbent() {
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, Some(100)),
            entry(B, SessionState::Connected, None),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(A.parse().unwrap()));
    }

    #[tokio::test]
    async fn measured_challenger_displaces_unmeasured_incumbent() {
        // A known latency beats an unknown one regardless of the threshold.
        let peer = test_peer(vec![
            entry(A, SessionState::Connected, None),
            entry(B, SessionState::Connected, Some(400)),
        ])
        .await;
        set_selected(&peer, A);
        peer.select_session();
        assert_eq!(selected(&peer), Some(B.parse().unwrap()));
    }

    fn set_info(peer: &Peer, nat_type: NatType, nat_addr: Option<&str>, local: &[&str]) {
        let info = peer
            .info()
            .with_nat_type(nat_type)
            .with_nat_addr(nat_addr.map(|a| a.parse().unwrap()))
            .with_local_addrs(local.iter().map(|a| a.parse().unwrap()).collect());
        *peer.info.write().unwrap() = info;
    }

    #[tokio::test]
    async fn candidates_combine_lan_and_nat_addrs() {
        let peer = test_peer(Vec::new()).await;
        set_info(&peer, NatType::Other, Some(A), &[B]);
        assert_eq!(
            peer.candidate_addrs(),
            vec![B.parse().unwrap(), A.parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn symmetric_nat_keeps_lan_but_drops_stun_candidate() {
        let peer = test_peer(Vec::new()).await;
        set_info(&peer, NatType::Symmetric, Some(A), &[B]);
        assert_eq!(peer.candidate_addrs(), vec![B.parse().unwrap()]);
    }

    #[tokio::test]
    async fn duplicate_lan_and_stun_addr_yields_one_candidate() {
        // A peer with a public interface reports the same address both ways.
        let peer = test_peer(Vec::new()).await;
        set_info(&peer, NatType::Other, Some(A), &[A]);
        assert_eq!(peer.candidate_addrs(), vec![A.parse().unwrap()]);
    }
}
