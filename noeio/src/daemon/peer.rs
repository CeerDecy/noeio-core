use crate::tunnel::session::{Datagram, SessionState, TunnelSession, UdpTunnelSession};
use noeio_common::host_info::{NatType, PeerId, PeerInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Local runtime view of a peer.
///
/// Wraps the broadcast [`PeerInfo`] identity learned via `SyncRoute`.
#[derive(Clone)]
pub struct Peer {
    /// Broadcast identity (peer_id / virtual IP / network).
    pub info: PeerInfo,
    /// Our own id in this peer's network, learned from the `SyncRoute` header.
    /// Stamped into the Seq/Ack/KeepAlive packets this peer's session emits so
    /// the remote can resolve *us* (the sender) in its router — signalling
    /// packets carry the sender's id, unlike Forward which carries the
    /// receiver's. A `u32`, so stored by value: a `&PeerId` would be larger and
    /// would force a lifetime on `Peer`, which the owning `Router` can't satisfy.
    pub local_peer_id: PeerId,
    /// Shared outer UDP socket, used to open a direct tunnel session to this
    /// peer on demand (e.g. after a `Failed` session needs re-establishing).
    pub socket: Arc<UdpSocket>,
    /// Direct tunnel session to this peer, if one has been established. The
    /// session only maintains reachability (hole punch + keepalive); business
    /// traffic goes over the outer UDP socket, not through it.
    pub session: Option<Arc<Box<dyn TunnelSession>>>,
    /// Inbound side of the session: the global reader pushes this peer's
    /// signalling datagrams onto this sender, and the session's `dispatch` task
    /// drains them. `Some` whenever `session` is set.
    pub inbound_tx: Option<mpsc::Sender<Datagram>>,
}

impl Peer {
    /// Create a peer from its broadcast identity.
    ///
    /// A peer that is not behind a symmetric NAT is directly reachable, so we
    /// eagerly open a [`UdpTunnelSession`] to it; symmetric-NAT peers can only
    /// be reached via the relay and start with no direct session.
    /// `local_peer_id` is our own id in this peer's network (learned from the
    /// `SyncRoute` header). It is stamped into the Seq/Ack/KeepAlive packets the
    /// session emits so the remote can resolve *us* in its router — signalling
    /// packets carry the sender's id, unlike Forward which carries the
    /// receiver's.
    pub fn new(info: PeerInfo, socket: Arc<UdpSocket>, local_peer_id: PeerId) -> Self {
        let mut peer = Self {
            info,
            socket,
            local_peer_id,
            session: None,
            inbound_tx: None,
        };
        peer.try_create_tunnel(false);
        peer
    }

    /// Open a direct tunnel session to this peer if one is warranted and store
    /// it. Does nothing (and never errors) when a session isn't needed:
    ///
    /// - a symmetric-NAT peer is only reachable via the relay, so no direct
    ///   session is attempted (regardless of `force`);
    /// - with `force == false`: a live session (`Connecting`/`Connected`) is
    ///   left as-is, and a fresh [`UdpTunnelSession`] is opened only when there's
    ///   no session or the existing one has `Failed`;
    /// - with `force == true`: the session state is ignored and a fresh session
    ///   always replaces any existing one (the old session and its tasks are
    ///   dropped, which aborts them).
    pub fn try_create_tunnel(&mut self, force: bool) {
        // A symmetric-NAT peer is relay-only; a peer whose STUN address we
        // haven't learned yet has nowhere to punch to. Either way, no direct
        // session.
        if self.info.nat_type == NatType::Symmetric || self.info.nat_addr.is_none() {
            return;
        }

        if !force {
            let needs_session = match &self.session {
                None => true,
                Some(session) => session.state() == SessionState::Failed,
            };
            if !needs_session {
                return;
            }
        }

        self.create_tunnel();
    }

    /// Open a fresh [`UdpTunnelSession`] and store it, replacing any existing
    /// session. Assigning over the old session drops it, which aborts its
    /// background tasks (if no other clone is holding it).
    ///
    /// Unconditional — callers gate on state via [`Self::try_create_tunnel`].
    fn create_tunnel(&mut self) {
        // Callers only reach here via `try_create_tunnel`, which returns early
        // when `nat_addr` is `None`; punch to the peer's STUN-observed address.
        // Reaching here without one means the guard and this method have drifted
        // out of sync, so surface it rather than silently skipping the punch.
        let Some(target) = self.info.nat_addr else {
            tracing::warn!(
                peer_id = self.info.peer_id,
                "cannot open tunnel: peer has no nat_addr"
            );
            return;
        };
        // `inbound_tx` is how the global reader feeds this peer's signalling
        // datagrams into the session; the demux path pushes onto it so the
        // session's `dispatch` task can make progress.
        // Stamp our own id (not the target's): the remote resolves the sender of
        // a signalling packet by looking `local_peer_id` up in its router.
        let (session, inbound_tx) =
            UdpTunnelSession::connect(self.socket.clone(), target, &self.local_peer_id);
        self.set_session(Arc::new(Box::new(session)), inbound_tx);
    }

    /// The address to reach this peer directly, if a direct path is currently
    /// usable. Returns `Some(nat_addr)` only when the peer is not behind a
    /// symmetric NAT (direct punching is possible) and its tunnel session is
    /// `Connected` (the punch has succeeded and liveness holds). Otherwise
    /// `None`, meaning the caller should fall back to the relay.
    pub fn address(&self) -> Option<SocketAddr> {
        if self.info.nat_type == NatType::Symmetric {
            return None;
        }
        let session = self.session.as_ref()?;
        if session.state() != SessionState::Connected {
            return None;
        }
        self.info.nat_addr
    }

    /// Feed an inbound signalling datagram to this peer's tunnel session.
    ///
    /// The global reader calls this after demuxing a datagram to this peer; the
    /// payload lands on `inbound_tx` and the session's `dispatch` task drains it.
    /// Returns `false` when there's nothing to deliver to (no session, e.g. a
    /// symmetric-NAT peer) or the session's inbound channel is closed (its tasks
    /// are gone); `true` when the datagram was queued.
    pub async fn inbound(&self, payload: Vec<u8>, src: SocketAddr) -> bool {
        let Some(tx) = self.inbound_tx.as_ref() else {
            return false;
        };
        tx.send((payload, src)).await.is_ok()
    }

    /// Refresh the broadcast identity from a newer `SyncRoute`.
    ///
    /// If the peer's `network_id` or `nat_type` changed, the previous tunnel
    /// session is no longer valid for the new identity, so we force a fresh one
    /// (subject to the symmetric-NAT rule in [`Self::try_create_tunnel`]).
    pub fn update_info(&mut self, info: PeerInfo, local_peer_id: PeerId) {
        let identity_changed =
            self.info.network_id != info.network_id || self.info.nat_type != info.nat_type;
        self.info = info;
        // Refresh our own id too: a re-addressed SyncRoute may carry a new one,
        // and a rebuilt session must stamp the current value.
        self.local_peer_id = local_peer_id;
        if identity_changed {
            self.try_create_tunnel(true);
        }
    }

    /// Attach a direct tunnel session to this peer, along with the inbound
    /// sender the demux path feeds datagrams through. Kept together so `session`
    /// and `inbound_tx` stay consistent.
    pub fn set_session(
        &mut self,
        session: Arc<Box<dyn TunnelSession>>,
        inbound_tx: mpsc::Sender<Datagram>,
    ) {
        self.session = Some(session);
        self.inbound_tx = Some(inbound_tx);
    }
}
