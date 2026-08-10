use std::net::{IpAddr, SocketAddr};

mod udp;
mod wireguard;

pub use udp::UdpTunnelSession;
pub use wireguard::WireGuardTunnelSession;

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

/// What the caller must do with the bytes a session codec produced into `dst`.
///
/// Sessions are sans-IO: they never touch the nic or the socket themselves.
/// The caller owns both and executes whatever this enum instructs, which keeps
/// `DeviceWriter` ownership and the IO topology out of the session entirely.
#[derive(Debug)]
pub enum TunnOutput<'a> {
    /// A plaintext IP packet — write it to the local nic. The address is the
    /// inner source IP when the codec can report it (for allowed-ips style
    /// anti-spoofing checks); `None` for codecs that don't parse the packet.
    ToNic(&'a [u8], Option<IpAddr>),
    /// Tunnel protocol traffic (handshake, keepalive, cookie) or an encrypted
    /// data packet — send it to the peer over the outer socket.
    ToPeer(&'a [u8]),
    /// The input was consumed with nothing left to emit.
    Consumed,
    /// The input was rejected; the message is for logging only.
    Err(String),
}

/// A peer-to-peer tunnel session: it establishes reachability (NAT hole punch)
/// and keeps it alive, and may additionally act as the data-plane codec.
///
/// The codec half is sans-IO: [`Self::decapsulate`] / [`Self::encapsulate`]
/// only transform bytes between the outer-socket representation and the inner
/// IP packet, and tell the caller — who owns the socket and the nic writer —
/// what to do with the result via [`TunnOutput`]. The default implementations
/// are the identity codec of a plaintext tunnel (e.g. [`UdpTunnelSession`],
/// whose business traffic travels on the outer socket unwrapped); an
/// encrypting session such as [`WireGuardTunnelSession`] overrides them.
pub trait TunnelSession: Send + Sync {
    /// Current handshake/liveness state of the session.
    fn state(&self) -> SessionState;

    /// Transform one inbound datagram received from the peer.
    ///
    /// Contract (mirrors boringtun): when this returns [`TunnOutput::ToPeer`],
    /// call it again with an empty `datagram` until it returns
    /// [`TunnOutput::Consumed`] — one input may produce several outputs (e.g.
    /// a handshake reply followed by queued data packets).
    fn decapsulate<'a>(
        &self,
        _src: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnOutput<'a> {
        if datagram.is_empty() {
            return TunnOutput::Consumed;
        }
        if dst.len() < datagram.len() {
            return TunnOutput::Err(format!(
                "dst too small for datagram: {} < {}",
                dst.len(),
                datagram.len()
            ));
        }
        let out = &mut dst[..datagram.len()];
        out.copy_from_slice(datagram);
        TunnOutput::ToNic(out, None)
    }

    /// Transform one outbound IP packet read from the nic.
    fn encapsulate<'a>(&self, plaintext: &[u8], dst: &'a mut [u8]) -> TunnOutput<'a> {
        if dst.len() < plaintext.len() {
            return TunnOutput::Err(format!(
                "dst too small for packet: {} < {}",
                dst.len(),
                plaintext.len()
            ));
        }
        let out = &mut dst[..plaintext.len()];
        out.copy_from_slice(plaintext);
        TunnOutput::ToPeer(out)
    }

    /// Drive the codec's clock: rekeys, retransmissions, keepalives.
    ///
    /// Call periodically (WireGuard expects ~every 250ms); any produced
    /// protocol packet is returned as [`TunnOutput::ToPeer`]. The plaintext
    /// default has no clock and never emits anything.
    fn update_timers<'a>(&self, _dst: &'a mut [u8]) -> TunnOutput<'a> {
        TunnOutput::Consumed
    }
}
