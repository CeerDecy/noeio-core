use super::{SessionState, TunnOutput, TunnelSession};
use boringtun::noise::{Tunn, TunnResult};
use std::net::IpAddr;
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

/// A [`TunnelSession`] whose data plane is a WireGuard tunnel.
///
/// Sans-IO: this wraps boringtun's `Tunn` state machine and only transforms
/// bytes. Handshakes are data-driven — the first [`Self::encapsulate`] call
/// with no established session queues the packet and emits the handshake
/// initiation as [`TunnOutput::ToPeer`]; rekeys and retransmissions come out
/// of [`Self::update_timers`], which the owner must call periodically.
pub struct WireGuardTunnelSession {
    /// `Tunn`'s methods take `&mut self`; its operations are short and never
    /// await, so a std mutex is safe to use from async callers.
    tunn: Mutex<Tunn>,
}

impl WireGuardTunnelSession {
    /// Build a session from our static secret and the peer's public key —
    /// derive both with
    /// [`derive_tunnel_keys`](crate::tunnel::wireguard::derive_tunnel_keys)
    /// so the two ends of the pair agree.
    ///
    /// `index` distinguishes concurrent tunnels on one host; boringtun folds
    /// it into session ids, so give each peer a distinct value.
    pub fn new(secret: StaticSecret, peer_public: PublicKey, index: u32) -> Self {
        let tunn = Tunn::new(secret, peer_public, None, None, index, None);
        Self {
            tunn: Mutex::new(tunn),
        }
    }
}

/// Translate boringtun's verdict into the session-level [`TunnOutput`].
fn map_result(result: TunnResult<'_>) -> TunnOutput<'_> {
    match result {
        TunnResult::Done => TunnOutput::Consumed,
        TunnResult::Err(err) => TunnOutput::Err(format!("{:?}", err)),
        TunnResult::WriteToNetwork(buf) => TunnOutput::ToPeer(buf),
        TunnResult::WriteToTunnelV4(buf, src) => TunnOutput::ToNic(buf, Some(IpAddr::V4(src))),
        TunnResult::WriteToTunnelV6(buf, src) => TunnOutput::ToNic(buf, Some(IpAddr::V6(src))),
    }
}

impl TunnelSession for WireGuardTunnelSession {
    fn state(&self) -> SessionState {
        let tunn = self.tunn.lock().unwrap();
        // stats().0 is the time since the last completed handshake.
        match tunn.stats().0 {
            Some(_) => SessionState::Connected,
            None if tunn.is_expired() => SessionState::Timeout,
            None => SessionState::Connecting,
        }
    }

    fn decapsulate<'a>(
        &self,
        src: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnOutput<'a> {
        let mut tunn = self.tunn.lock().unwrap();
        map_result(tunn.decapsulate(src, datagram, dst))
    }

    fn encapsulate<'a>(&self, plaintext: &[u8], dst: &'a mut [u8]) -> TunnOutput<'a> {
        let mut tunn = self.tunn.lock().unwrap();
        map_result(tunn.encapsulate(plaintext, dst))
    }

    fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnOutput<'a> {
        let mut tunn = self.tunn.lock().unwrap();
        map_result(tunn.update_timers(dst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Owned copy of a [`TunnOutput`], so test buffers can be reused.
    #[derive(Debug, PartialEq)]
    enum Out {
        ToNic(Vec<u8>, Option<IpAddr>),
        ToPeer(Vec<u8>),
    }

    /// Feed one datagram through `decapsulate`, honouring the repeat-on-ToPeer
    /// contract, and collect every produced output.
    fn drain_decapsulate(session: &dyn TunnelSession, datagram: &[u8]) -> Vec<Out> {
        let mut outputs = Vec::new();
        let mut input = datagram;
        loop {
            let mut buf = [0u8; 2048];
            match session.decapsulate(None, input, &mut buf) {
                TunnOutput::ToPeer(data) => {
                    outputs.push(Out::ToPeer(data.to_vec()));
                    // Repeated call with an empty datagram flushes queued output.
                    input = &[];
                }
                TunnOutput::ToNic(data, src) => {
                    outputs.push(Out::ToNic(data.to_vec(), src));
                    break;
                }
                TunnOutput::Consumed => break,
                TunnOutput::Err(err) => panic!("decapsulate failed: {err}"),
            }
        }
        outputs
    }

    /// A minimal valid IPv4 packet (20-byte header + payload) that boringtun's
    /// decapsulation-side sanity check accepts.
    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45; // version 4, IHL 5
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64; // TTL
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn handshake_and_data_round_trip() {
        let a_secret = StaticSecret::from([0x11u8; 32]);
        let b_secret = StaticSecret::from([0x22u8; 32]);
        let a = WireGuardTunnelSession::new(a_secret.clone(), PublicKey::from(&b_secret), 0);
        let b = WireGuardTunnelSession::new(b_secret, PublicKey::from(&a_secret), 1);

        assert_eq!(a.state(), SessionState::Connecting);

        let src = Ipv4Addr::new(10, 0, 0, 1);
        let plaintext = ipv4_packet(src, Ipv4Addr::new(10, 0, 0, 2), b"hello");

        // No session yet: the packet is queued and the handshake initiation
        // comes out instead.
        let mut buf = [0u8; 2048];
        let TunnOutput::ToPeer(init) = a.encapsulate(&plaintext, &mut buf) else {
            panic!("expected handshake initiation");
        };
        let init = init.to_vec();

        // B answers the initiation with the handshake response.
        let outputs = drain_decapsulate(&b, &init);
        let [Out::ToPeer(response)] = outputs.as_slice() else {
            panic!("expected handshake response, got {outputs:?}");
        };

        // Completing the handshake on A emits a keepalive confirming the new
        // session, then flushes the queued data packet.
        let outputs = drain_decapsulate(&a, response);
        assert_eq!(a.state(), SessionState::Connected);
        let [Out::ToPeer(keepalive), Out::ToPeer(data)] = outputs.as_slice() else {
            panic!("expected keepalive + queued data packet, got {outputs:?}");
        };

        // The keepalive decrypts to nothing.
        assert_eq!(drain_decapsulate(&b, keepalive), Vec::<Out>::new());

        // B decrypts the data packet back to the original plaintext and
        // reports the inner source address for anti-spoofing checks.
        let outputs = drain_decapsulate(&b, data);
        assert_eq!(
            outputs.as_slice(),
            &[Out::ToNic(plaintext, Some(IpAddr::V4(src)))]
        );
        assert_eq!(b.state(), SessionState::Connected);
    }
}
