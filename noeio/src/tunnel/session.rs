use std::net::SocketAddr;

mod udp;

pub use udp::UdpTunnelSession;

/// A datagram routed to a session: payload plus its source address.
///
/// The global reader demuxes inbound datagrams and pushes the ones belonging to
/// a session (its handshake control packets and keepalives) onto the session's
/// inbound channel.
pub type Datagram = (Vec<u8>, SocketAddr);

/// Handshake/liveness state of a [`TunnelSession`].
///
/// A session performing a hole punch starts as `Connecting`, becomes
/// `Connected` once the peer confirms, or `Failed` if the handshake gives up or
/// an established session later goes silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Handshake in progress; not yet confirmed by the peer.
    Connecting = 0,
    /// The tunnel is up.
    Connected = 1,
    /// The handshake gave up, or an established session timed out.
    Failed = 2,
}

impl SessionState {
    /// Reconstruct a state from its atomic `u8` representation, falling back to
    /// `Connecting` for any unexpected value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Connected,
            2 => Self::Failed,
            _ => Self::Connecting,
        }
    }
}

/// A peer-to-peer tunnel session: it establishes reachability (NAT hole punch)
/// and keeps it alive, but does not carry business traffic.
///
/// Business packets are sent and received on the outer UDP socket directly; a
/// session only owns the signalling (Seq/Ack handshake), keepalives, and
/// liveness tracking. Its sole observable output is [`Self::state`].
pub trait TunnelSession: Send + Sync {
    /// Current handshake/liveness state of the session.
    fn state(&self) -> SessionState;
}
