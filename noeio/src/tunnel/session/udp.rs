use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use noeio_common::host_info::PeerId;
use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{Datagram, SessionState, TunnelSession};

/// Buffer size for the per-session inbound datagram channel.
const CHANNEL_CAPACITY: usize = 256;

/// Length of the handshake nonce carried in a Seq/Ack payload (a big-endian
/// `u64`).
const NONCE_LEN: usize = 8;

/// How long `handshake` waits for an Ack before retransmitting the Seq.
const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// How many Seq packets `handshake` sends before giving up.
const HANDSHAKE_MAX_ATTEMPTS: usize = 5;

/// How often `keepalive` sends a KeepAlive packet to hold the NAT mapping open.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How long the peer may go silent (no inbound datagram of any kind) before
/// `monitor` declares the session dead. Set to a few keepalive intervals so
/// a couple of dropped keepalives don't trip it.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(45);

/// How often `monitor` checks the elapsed time since the last inbound datagram.
const LIVENESS_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Build a Seq/Ack/KeepAlive control packet carrying `nonce` in its payload.
///
/// `peer_id` is *our own* id (the sender's), not the target's. Signalling
/// packets carry the sender's id so the receiver can resolve us in its router
/// via `get_by_peer_id` — the opposite of Forward, which carries the receiver's
/// id because the receiver routes it against its local nic table.
fn control_packet(packet_type: NoeioPacketType, peer_id: PeerId, nonce: u64) -> NoeioPacket {
    NoeioPacket::new(
        PacketHeader {
            packet_type,
            // Sender's id: the receiver looks this up in its router to find the
            // Peer this signalling belongs to.
            peer_id,
            ..PacketHeader::default()
        },
        &nonce.to_be_bytes(),
    )
}

/// Read the handshake nonce from a control packet's payload, if present.
fn nonce_of(packet: &NoeioPacket) -> Option<u64> {
    let bytes = packet.payload()?.get(..NONCE_LEN)?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// A [`TunnelSession`] backed by a plain UDP socket.
///
/// It performs the Seq/Ack hole-punch handshake, keeps the NAT mapping alive,
/// and tracks liveness — but carries no business traffic. Data packets travel
/// on the outer UDP socket directly; this session only owns signalling.
///
/// The socket is read globally elsewhere; datagrams destined for this session
/// (its control packets and keepalives) are routed in through a channel and
/// handled by a background `dispatch` task rather than read from the socket
/// directly.
pub struct UdpTunnelSession {
    /// Handshake/liveness state. A lock-free `AtomicU8` holding a
    /// [`SessionState`]: written by the `handshake`/`monitor` tasks, read
    /// through `&self`, with no mutex.
    state: Arc<AtomicU8>,
    /// Background tasks owned by this session (`send`, `dispatch`, `handshake`,
    /// `monitor`). Dropping the session aborts them, so the tasks—and the
    /// socket the `send` task holds—don't leak.
    _tasks: JoinSet<()>,
}

impl UdpTunnelSession {
    /// Open a session over `socket` toward peer `target`, spawning the
    /// background `send`, `dispatch`, `handshake`, and `monitor` tasks and
    /// returning the session along with the [`mpsc::Sender`] the global reader
    /// uses to route this peer's inbound signalling datagrams into it.
    ///
    /// `peer_id` is *our own* id in the target's network, not the target's id.
    /// It's stamped into the header of every Seq/Ack/KeepAlive we emit so the
    /// receiver can resolve us (the sender) in its router. See `control_packet`.
    pub fn connect(
        socket: Arc<UdpSocket>,
        target: SocketAddr,
        peer_id: &PeerId,
    ) -> (Self, mpsc::Sender<Datagram>) {
        let peer_id = *peer_id;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel(CHANNEL_CAPACITY);
        // Capacity 1: dispatch only needs to record that at least one Ack
        // arrived; extra Acks while one is already pending can be dropped.
        let (ack_tx, ack_rx) = mpsc::channel(1);
        let state = Arc::new(AtomicU8::new(SessionState::Connecting as u8));
        // Passive liveness clock: `dispatch` stamps the elapsed millis since
        // `base` on every inbound datagram, and `monitor` compares that against
        // `LIVENESS_TIMEOUT`. `Instant` isn't atomic, so we track a lock-free
        // millisecond offset from a shared base instead.
        let base = Instant::now();
        let last_recv = Arc::new(AtomicU64::new(0));
        // Nonce tying our Seq to the Ack we expect back, so a stray or replayed
        // Ack (carrying a different nonce) can't complete the handshake.
        let nonce = rand::random::<u64>();

        let mut tasks = JoinSet::new();
        // The send task owns the socket and target; everyone else sends by
        // pushing payloads onto `out_tx`.
        tasks.spawn(Self::send(socket, target, out_rx));
        tasks.spawn(Self::dispatch(
            rx,
            out_tx.clone(),
            ack_tx,
            peer_id,
            nonce,
            base,
            last_recv.clone(),
        ));
        tasks.spawn(Self::handshake(out_tx, ack_rx, state.clone(), peer_id, nonce));
        tasks.spawn(Self::monitor(state.clone(), base, last_recv));

        let session = Self {
            state,
            _tasks: tasks,
        };
        (session, tx)
    }

    /// Drain outbound payloads and write them to the peer.
    ///
    /// This is the sole owner of the socket and target, so all signalling is
    /// funnelled through here; callers just push `Vec<u8>` onto the channel.
    ///
    /// Runs as a background task until the outbound channel closes.
    async fn send(socket: Arc<UdpSocket>, target: SocketAddr, mut out_rx: mpsc::Receiver<Vec<u8>>) {
        while let Some(payload) = out_rx.recv().await {
            if let Err(e) = socket.send_to(&payload, target).await {
                tracing::warn!(%target, error = %e, "udp send failed, stopping send task");
                break;
            }
        }
    }

    /// Handle this session's inbound signalling datagrams from the global
    /// reader's channel (`recv`). This session carries no business traffic, so
    /// every datagram is either a control packet acted on here or dropped.
    ///
    /// - Any inbound datagram stamps the liveness clock (`last_recv`).
    /// - `Ack` is accepted only when its nonce matches `nonce` (the nonce our
    ///   Seq carried); it then signals `handshake` through `ack_tx`. An Ack with
    ///   a different or missing nonce is dropped.
    /// - `Seq` (an incoming hole-punch request) is answered with an `Ack` that
    ///   echoes the Seq's nonce, pushed onto `out_tx`.
    /// - `KeepAlive` and anything else is dropped (the liveness stamp above is
    ///   the only effect keepalives have).
    ///
    /// TODO: the Ack now goes to the fixed `target` (via the send task) rather
    /// than the Seq's actual source address. For strict hole punching the reply
    /// may need to target the observed source; revisit if that matters.
    ///
    /// Runs as a background task until the inbound channel closes.
    async fn dispatch(
        mut recv: mpsc::Receiver<Datagram>,
        out_tx: mpsc::Sender<Vec<u8>>,
        ack_tx: mpsc::Sender<()>,
        peer_id: PeerId,
        nonce: u64,
        base: Instant,
        last_recv: Arc<AtomicU64>,
    ) {
        while let Some(datagram) = recv.recv().await {
            // Any inbound datagram proves the peer is alive; stamp the liveness
            // clock before inspecting the packet.
            last_recv.store(base.elapsed().as_millis() as u64, Ordering::Release);

            let Ok(packet) = NoeioPacket::try_from(datagram.0.as_slice()) else {
                continue;
            };
            match packet.packet_type {
                NoeioPacketType::Ack => {
                    // Only our own nonce coming back counts; anything else is a
                    // stray/replayed Ack and is ignored.
                    if nonce_of(&packet) == Some(nonce) {
                        // A pending signal already means "Ack seen"; ignore if full.
                        let _ = ack_tx.try_send(());
                    }
                }
                NoeioPacketType::Seq => {
                    // Peer initiated a hole punch — answer with an Ack that
                    // echoes their nonce so they can correlate it. A Seq without
                    // a nonce is malformed; drop it.
                    match nonce_of(&packet) {
                        Some(peer_nonce) => {
                            let ack = control_packet(NoeioPacketType::Ack, peer_id, peer_nonce);
                            let _ = out_tx.send(ack.inner.to_vec()).await;
                        }
                        None => {
                            tracing::debug!(src = %datagram.1, "dropping malformed Seq with no nonce");
                        }
                    }
                }
                // KeepAlive (liveness already stamped) and any other packet type
                // carry nothing this session acts on.
                _ => {}
            }
        }
    }

    /// Perform the hole-punch handshake as a background task: send a Seq packet
    /// and wait for the peer's Ack (surfaced by `dispatch` through `ack_rx`),
    /// then mark the session connected and hand off to keepalive.
    ///
    /// Runs in the session's `JoinSet`, so it owns everything it touches rather
    /// than borrowing `self`; `state` is shared back via `Arc`.
    ///
    /// The Seq carries `nonce`; `dispatch` only accepts an Ack that echoes it
    /// back, so this task is woken solely by the matching response.
    ///
    /// The Seq is retransmitted up to [`HANDSHAKE_MAX_ATTEMPTS`] times, waiting
    /// [`HANDSHAKE_RETRY_INTERVAL`] for an Ack between attempts (UDP may drop the
    /// Seq or its Ack). On success `state` becomes [`SessionState::Connected`];
    /// if every attempt times out it becomes [`SessionState::Failed`].
    async fn handshake(
        out_tx: mpsc::Sender<Vec<u8>>,
        mut ack_rx: mpsc::Receiver<()>,
        state: Arc<AtomicU8>,
        peer_id: PeerId,
        nonce: u64,
    ) {
        let seq = control_packet(NoeioPacketType::Seq, peer_id, nonce);

        for _ in 0..HANDSHAKE_MAX_ATTEMPTS {
            if out_tx.send(seq.inner.to_vec()).await.is_err() {
                // Send task is gone; the session is shutting down.
                return;
            }

            // Wait for dispatch to signal a matching Ack. On timeout, loop and
            // retransmit; the same nonce is reused so a late Ack still counts.
            match tokio::time::timeout(HANDSHAKE_RETRY_INTERVAL, ack_rx.recv()).await {
                // Ack arrived — the session is up. Hand off to keepalive, which
                // runs for the rest of this task's life.
                Ok(Some(())) => {
                    tracing::debug!(nonce, "udp handshake complete");
                    state.store(SessionState::Connected as u8, Ordering::Release);
                    Self::keepalive(out_tx, peer_id).await;
                    return;
                }
                // Channel closed — dispatch dropped its sender, so no Ack will
                // ever come; stop retrying.
                Ok(None) => return,
                // Timed out waiting for the Ack; retransmit.
                Err(_) => continue,
            }
        }
        // Exhausted all attempts without an Ack; mark the handshake failed.
        state.store(SessionState::Failed as u8, Ordering::Release);
        tracing::warn!(
            nonce,
            attempts = HANDSHAKE_MAX_ATTEMPTS,
            "udp handshake failed: no ack after all retries"
        );
    }

    /// Periodically send a KeepAlive packet to hold the NAT mapping open.
    ///
    /// Started by `handshake` once the session is up; runs until the send task
    /// is gone (its channel closed), i.e. the session is shutting down.
    async fn keepalive(out_tx: mpsc::Sender<Vec<u8>>, peer_id: PeerId) {
        let packet = NoeioPacket::new(
            PacketHeader {
                packet_type: NoeioPacketType::KeepAlive,
                // Sender's own id, same as Seq/Ack: the receiver resolves us in
                // its router by this. See `control_packet`.
                peer_id,
                ..PacketHeader::default()
            },
            &[],
        );
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            if out_tx.send(packet.inner.to_vec()).await.is_err() {
                // Send task gone — session is closing.
                break;
            }
        }
    }

    /// Passively watch for a dead peer: if no inbound datagram has arrived within
    /// [`LIVENESS_TIMEOUT`], flip `state` to [`SessionState::Failed`].
    ///
    /// Both peers send keepalives, so a healthy link stamps `last_recv` at least
    /// once per [`KEEPALIVE_INTERVAL`]; silence past the timeout means the peer
    /// is gone. Only a `Connected` session is demoted — `Connecting` is the
    /// handshake's business, and `Failed` is terminal.
    async fn monitor(state: Arc<AtomicU8>, base: Instant, last_recv: Arc<AtomicU64>) {
        loop {
            tokio::time::sleep(LIVENESS_CHECK_INTERVAL).await;

            // Only supervise an established session.
            if SessionState::from_u8(state.load(Ordering::Acquire)) != SessionState::Connected {
                continue;
            }

            let last = Duration::from_millis(last_recv.load(Ordering::Acquire));
            let silent = base.elapsed().saturating_sub(last);
            if silent >= LIVENESS_TIMEOUT {
                state.store(SessionState::Failed as u8, Ordering::Release);
                tracing::warn!(
                    silent_ms = silent.as_millis() as u64,
                    "udp session timed out: no inbound datagram within liveness window"
                );
            }
        }
    }
}

impl TunnelSession for UdpTunnelSession {
    fn state(&self) -> SessionState {
        // Written by the `handshake` and `monitor` tasks; `Connecting` until the
        // peer's Ack arrives, then `Connected`, or `Failed` on handshake
        // exhaustion or liveness timeout.
        SessionState::from_u8(self.state.load(Ordering::Acquire))
    }
}
