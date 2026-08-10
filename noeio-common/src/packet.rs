pub mod report;
mod token_frame;

use bytes::BytesMut;
use smoltcp::wire::Ipv4Packet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use crate::host_info::PeerId;

pub static MAX_PACKET_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoeioPacketType {
    Ping,
    Forward,
    SyncRoute,      //
    Report,         // report host info
    Seq,            // UDP hole punch request (initiator)
    Ack,            // UDP hole punch response (acknowledgement)
    KeepAlive,      // periodic packet to keep the NAT mapping open
    Delivery,       // data packet from the peer named in the header; process locally, never forward
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub packet_type: NoeioPacketType,
    pub peer_id: PeerId,
    pub port: u16,
}

impl Default for PacketHeader {
    fn default() -> Self {
        PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: 0,
            port: 0,
        }
    }
}

impl PacketHeader {
    pub const MAGIC: [u8; 2] = [0x4E, 0x4F]; // "NO"
    pub const LEN: usize = 9; // 2 magic + 1 type + 4 peer_id + 2 port

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..2].copy_from_slice(&Self::MAGIC);
        out[2] = u8::from(self.packet_type);
        out[3..7].copy_from_slice(&self.peer_id.to_be_bytes());
        out[7..9].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }

        if bytes[0..2] != Self::MAGIC {
            return None;
        }

        let packet_type = NoeioPacketType::try_from(bytes[2]).ok()?;
        Some(PacketHeader {
            packet_type,
            peer_id: u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
            port: u16::from_be_bytes([bytes[7], bytes[8]]),
        })
    }
}

impl From<PacketHeader> for Vec<u8> {
    fn from(value: PacketHeader) -> Self {
        value.to_bytes().to_vec()
    }
}

impl From<&PacketHeader> for Vec<u8> {
    fn from(value: &PacketHeader) -> Self {
        value.to_bytes().to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPacketPayload {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl PingPacketPayload {
    pub const LEN: usize = 8;
    const TERMINATOR: [u8; 2] = *b"\r\n";

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..4].copy_from_slice(&self.ip.octets());
        out[4..6].copy_from_slice(&self.port.to_be_bytes());
        out[6..8].copy_from_slice(&Self::TERMINATOR);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }

        if bytes[6..8] != Self::TERMINATOR {
            return None;
        }

        Some(Self {
            ip: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            port: u16::from_be_bytes([bytes[4], bytes[5]]),
        })
    }

    pub fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.ip, self.port))
    }
}

impl From<SocketAddrV4> for PingPacketPayload {
    fn from(value: SocketAddrV4) -> Self {
        Self {
            ip: *value.ip(),
            port: value.port(),
        }
    }
}

impl From<&SocketAddrV4> for PingPacketPayload {
    fn from(value: &SocketAddrV4) -> Self {
        Self {
            ip: *value.ip(),
            port: value.port(),
        }
    }
}

impl From<PingPacketPayload> for SocketAddr {
    fn from(value: PingPacketPayload) -> Self {
        value.to_socket_addr()
    }
}

impl From<&PingPacketPayload> for SocketAddr {
    fn from(value: &PingPacketPayload) -> Self {
        value.to_socket_addr()
    }
}

impl From<PingPacketPayload> for Vec<u8> {
    fn from(value: PingPacketPayload) -> Self {
        value.to_bytes().to_vec()
    }
}

impl From<&PingPacketPayload> for Vec<u8> {
    fn from(value: &PingPacketPayload) -> Self {
        value.to_bytes().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct NoeioPacket {
    pub inner: BytesMut,
    pub packet_type: NoeioPacketType,
}

impl NoeioPacket {
    /// Length of the noeio [`PacketHeader`] at the start of every packet.
    pub const HEADER_LEN: usize = PacketHeader::LEN;
    /// Offset of the noeio payload within `inner`.
    pub const PAYLOAD_OFFSET: usize = Self::HEADER_LEN;

    /// Build a packet from a header and payload.
    ///
    /// `inner` is the wire representation, laid out as
    /// `[9-byte noeio header][payload]`. `packet_type` mirrors the header so
    /// callers can match on it without re-parsing.
    pub fn new(header: PacketHeader, payload: &[u8]) -> Self {
        let header_bytes = header.to_bytes();

        let mut inner = BytesMut::with_capacity(header_bytes.len() + payload.len());
        inner.extend_from_slice(&header_bytes);
        inner.extend_from_slice(payload);

        Self {
            inner,
            packet_type: header.packet_type,
        }
    }

    pub fn parse_header(&self) -> Option<PacketHeader> {
        PacketHeader::from_bytes(&self.inner)
    }

    pub fn set_header(&mut self, header: PacketHeader) {
        let header_bytes = header.to_bytes();

        if self.inner.len() < Self::PAYLOAD_OFFSET {
            self.inner.resize(Self::PAYLOAD_OFFSET, 0);
        }

        self.inner[..Self::PAYLOAD_OFFSET].copy_from_slice(&header_bytes);
        self.packet_type = header.packet_type;
    }

    pub fn payload(&self) -> Option<&[u8]> {
        self.inner.get(Self::PAYLOAD_OFFSET..)
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        self.ensure_header();
        self.inner.truncate(Self::PAYLOAD_OFFSET);
        self.inner.extend_from_slice(payload);
    }

    pub fn parse_ping_payload(&self) -> Option<PingPacketPayload> {
        if self.packet_type != NoeioPacketType::Ping {
            return None;
        }

        PingPacketPayload::from_bytes(self.payload()?)
    }

    pub fn src_ip(&self) -> Option<Ipv4Addr> {
        let payload = self.payload()?;
        let ipv4 = Ipv4Packet::new_checked(payload).ok()?;
        Some(Ipv4Addr::from(ipv4.src_addr()))
    }

    pub fn dst_ip(&self) -> Option<Ipv4Addr> {
        let payload = self.payload()?;
        let ipv4 = Ipv4Packet::new_checked(payload).ok()?;
        Some(Ipv4Addr::from(ipv4.dst_addr()))
    }

    fn ensure_header(&mut self) {
        if self.inner.len() >= Self::PAYLOAD_OFFSET {
            return;
        }

        let header = self.parse_header().unwrap_or(PacketHeader {
            packet_type: self.packet_type,
            ..PacketHeader::default()
        });
        self.inner.resize(Self::PAYLOAD_OFFSET, 0);
        self.inner[..Self::PAYLOAD_OFFSET].copy_from_slice(&header.to_bytes());
    }
}

impl TryFrom<u8> for NoeioPacketType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NoeioPacketType::Ping),
            1 => Ok(NoeioPacketType::Forward),
            2 => Ok(NoeioPacketType::SyncRoute),
            3 => Ok(NoeioPacketType::Report),
            4 => Ok(NoeioPacketType::Seq),
            5 => Ok(NoeioPacketType::Ack),
            6 => Ok(NoeioPacketType::KeepAlive),
            7 => Ok(NoeioPacketType::Delivery),
            _ => Err(value),
        }
    }
}

impl From<NoeioPacketType> for u8 {
    fn from(value: NoeioPacketType) -> Self {
        match value {
            NoeioPacketType::Ping => 0,
            NoeioPacketType::Forward => 1,
            NoeioPacketType::SyncRoute => 2,
            NoeioPacketType::Report => 3,
            NoeioPacketType::Seq => 4,
            NoeioPacketType::Ack => 5,
            NoeioPacketType::KeepAlive => 6,
            NoeioPacketType::Delivery => 7,
        }
    }
}

impl TryFrom<Vec<u8>> for NoeioPacket {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        NoeioPacket::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for NoeioPacket {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let header = PacketHeader::from_bytes(value)
            .ok_or("invalid noeio packet: failed to parse header")?;

        Ok(NoeioPacket {
            inner: BytesMut::from(value),
            packet_type: header.packet_type,
        })
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;

    #[test]
    fn every_packet_type_roundtrips_through_wire_encoding() {
        for packet_type in [
            NoeioPacketType::Ping,
            NoeioPacketType::Forward,
            NoeioPacketType::SyncRoute,
            NoeioPacketType::Report,
            NoeioPacketType::Seq,
            NoeioPacketType::Ack,
            NoeioPacketType::KeepAlive,
            NoeioPacketType::Delivery,
        ] {
            assert_eq!(NoeioPacketType::try_from(u8::from(packet_type)), Ok(packet_type));
        }
    }

    #[test]
    fn set_header_rewrites_type_and_peer_id_but_keeps_payload() {
        // The derper relies on this to turn a Forward into a Delivery stamped
        // with the sender's id without touching the (encrypted) payload.
        let forward = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: 42, // destination
            port: 0,
        };
        let mut packet = NoeioPacket::new(forward, b"ciphertext");

        packet.set_header(PacketHeader {
            packet_type: NoeioPacketType::Delivery,
            peer_id: 7, // sender
            port: 0,
        });

        let header = packet.parse_header().unwrap();
        assert_eq!(header.packet_type, NoeioPacketType::Delivery);
        assert_eq!(header.peer_id, 7);
        assert_eq!(packet.packet_type, NoeioPacketType::Delivery);
        assert_eq!(packet.payload(), Some(&b"ciphertext"[..]));
    }
}

impl<const N: usize> TryFrom<[u8; N]> for NoeioPacket {
    type Error = &'static str;

    fn try_from(value: [u8; N]) -> Result<Self, Self::Error> {
        NoeioPacket::try_from(value.to_vec())
    }
}

impl From<NoeioPacket> for Vec<u8> {
    fn from(value: NoeioPacket) -> Self {
        value.inner.to_vec()
    }
}

impl From<&NoeioPacket> for Vec<u8> {
    fn from(value: &NoeioPacket) -> Self {
        value.inner.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_info::new_peer_id;

    /// Wire bytes for a packet: noeio header + payload.
    fn wire_bytes(header: &PacketHeader, payload: &[u8]) -> Vec<u8> {
        Vec::from(NoeioPacket::new(*header, payload))
    }

    #[test]
    fn packet_header_to_from_bytes_roundtrip() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: new_peer_id(),
            port: 51820,
        };

        let bytes = header.to_bytes();
        let parsed = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, header);
    }

    #[test]
    fn noeio_packet_parse_header_from_inner() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Ping,
            peer_id: new_peer_id(),
            port: 443,
        };

        let bytes = wire_bytes(&header, &[1, 2, 3, 4]);

        let packet = NoeioPacket::try_from(bytes).unwrap();
        let parsed = packet.parse_header().unwrap();

        assert_eq!(parsed, header);
        assert_eq!(packet.packet_type, NoeioPacketType::Ping);
    }

    #[test]
    fn packet_header_to_vec() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: new_peer_id(),
            port: 8080,
        };

        let bytes: Vec<u8> = header.into();
        assert_eq!(bytes.len(), PacketHeader::LEN);
        assert_eq!(PacketHeader::from_bytes(&bytes), Some(header));
    }

    #[test]
    fn noeio_packet_to_vec() {
        // noeio header [magic, type, peer_id, port], then payload.
        let bytes = vec![0x4E, 0x4F, 1, 10, 0, 0, 8, 0xCA, 0x6C, 9, 8, 7];

        let packet = NoeioPacket::try_from(bytes.clone()).unwrap();

        let out: Vec<u8> = packet.into();
        assert_eq!(out, bytes);
    }

    #[test]
    fn noeio_packet_new_layout_is_header_then_payload() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: 42,
            port: 8080,
        };
        let payload = [1u8, 2, 3, 4];
        let bytes = Vec::from(NoeioPacket::new(header, &payload));

        assert_eq!(bytes.len(), NoeioPacket::PAYLOAD_OFFSET + payload.len());
        assert_eq!(&bytes[0..2], &PacketHeader::MAGIC);

        // Header and payload survive a round-trip.
        let packet = NoeioPacket::try_from(bytes).unwrap();
        assert_eq!(packet.parse_header(), Some(header));
        assert_eq!(packet.payload(), Some(payload.as_slice()));
    }

    #[test]
    fn ping_packet_payload_to_from_bytes_roundtrip() {
        let payload = PingPacketPayload {
            ip: Ipv4Addr::new(10, 1, 2, 3),
            port: 51820,
        };

        let bytes = payload.to_bytes();
        assert_eq!(&bytes[6..8], b"\r\n");
        let parsed = PingPacketPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, payload);
    }

    #[test]
    fn ping_packet_payload_requires_crlf_terminator() {
        let mut bytes = PingPacketPayload {
            ip: Ipv4Addr::new(10, 1, 2, 3),
            port: 51820,
        }
        .to_bytes();
        bytes[6] = b'\n';
        bytes[7] = b'\r';

        assert_eq!(PingPacketPayload::from_bytes(&bytes), None);
    }

    #[test]
    fn ping_packet_payload_to_socket_addr() {
        let payload = PingPacketPayload {
            ip: Ipv4Addr::new(192, 168, 0, 9),
            port: 8080,
        };

        assert_eq!(
            payload.to_socket_addr(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 9), 8080))
        );
    }

    #[test]
    fn noeio_packet_parse_ping_payload() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Ping,
            peer_id: 0,
            port: 0,
        };
        let payload = PingPacketPayload {
            ip: Ipv4Addr::new(172, 16, 0, 10),
            port: 9000,
        };

        let bytes = wire_bytes(&header, &payload.to_bytes());

        let packet = NoeioPacket::try_from(bytes).unwrap();

        assert_eq!(packet.parse_ping_payload(), Some(payload));
    }

    #[test]
    fn noeio_packet_set_header_preserves_payload() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: new_peer_id(),
            port: 8080,
        };
        let bytes = wire_bytes(&header, &[1, 2, 3, 4]);

        let mut packet = NoeioPacket::try_from(bytes).unwrap();
        let new_header = PacketHeader {
            packet_type: NoeioPacketType::Ping,
            peer_id: new_peer_id(),
            port: 9000,
        };

        packet.set_header(new_header);

        assert_eq!(packet.parse_header(), Some(new_header));
        assert_eq!(packet.payload(), Some([1, 2, 3, 4].as_slice()));
        assert_eq!(packet.packet_type, NoeioPacketType::Ping);
    }

    #[test]
    fn noeio_packet_set_payload_preserves_header() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: new_peer_id(),
            port: 51820,
        };
        let bytes = wire_bytes(&header, &[9, 8, 7]);

        let mut packet = NoeioPacket::try_from(bytes).unwrap();
        packet.set_payload(&[4, 5, 6, 7]);

        assert_eq!(packet.parse_header(), Some(header));
        assert_eq!(packet.payload(), Some([4, 5, 6, 7].as_slice()));
        assert_eq!(packet.packet_type, NoeioPacketType::Forward);
    }
}
