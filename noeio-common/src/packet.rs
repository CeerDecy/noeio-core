use bytes::BytesMut;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoeioPacketType {
    Ping,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub packet_type: NoeioPacketType,
    pub forward_ip: Ipv4Addr,
    pub forward_port: u16,
}

impl Default for PacketHeader {
    fn default() -> Self {
        PacketHeader {
            packet_type: NoeioPacketType::Forward,
            forward_ip: Ipv4Addr::UNSPECIFIED,
            forward_port: 0,
        }
    }
}

impl PacketHeader {
    pub const LEN: usize = 7;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = u8::from(self.packet_type);
        out[1..5].copy_from_slice(&self.forward_ip.octets());
        out[5..7].copy_from_slice(&self.forward_port.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::LEN {
            return None;
        }

        Some(PacketHeader {
            packet_type: NoeioPacketType::from(bytes[0]),
            forward_ip: Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]),
            forward_port: u16::from_be_bytes([bytes[5], bytes[6]]),
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

#[derive(Debug)]
pub struct NoeioPacket {
    pub inner: BytesMut,
    pub packet_type: NoeioPacketType,
}

impl NoeioPacket {
    pub const HEADER_LEN: usize = PacketHeader::LEN;

    pub fn parse_header(&self) -> Option<PacketHeader> {
        PacketHeader::from_bytes(self.inner.as_ref())
    }
}

impl From<u8> for NoeioPacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => NoeioPacketType::Ping,
            1 => NoeioPacketType::Forward,
            _ => NoeioPacketType::Forward,
        }
    }
}

impl From<NoeioPacketType> for u8 {
    fn from(value: NoeioPacketType) -> Self {
        match value {
            NoeioPacketType::Ping => 0,
            NoeioPacketType::Forward => 1,
        }
    }
}

impl From<Vec<u8>> for NoeioPacket {
    fn from(value: Vec<u8>) -> Self {
        let packet_type = PacketHeader::from_bytes(&value)
            .map(|header| header.packet_type)
            .or_else(|| value.first().copied().map(NoeioPacketType::from))
            .unwrap_or(NoeioPacketType::Forward);

        NoeioPacket {
            inner: BytesMut::from(value.as_slice()),
            packet_type,
        }
    }
}

impl<const N: usize> From<[u8; N]> for NoeioPacket {
    fn from(value: [u8; N]) -> Self {
        NoeioPacket::from(value.to_vec())
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

    #[test]
    fn packet_header_to_from_bytes_roundtrip() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            forward_ip: Ipv4Addr::new(10, 0, 0, 8),
            forward_port: 51820,
        };

        let bytes = header.to_bytes();
        let parsed = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, header);
    }

    #[test]
    fn noeio_packet_parse_header_from_inner() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Ping,
            forward_ip: Ipv4Addr::new(192, 168, 1, 1),
            forward_port: 443,
        };

        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let packet = NoeioPacket::from(bytes);
        let parsed = packet.parse_header().unwrap();

        assert_eq!(parsed, header);
        assert_eq!(packet.packet_type, NoeioPacketType::Ping);
    }

    #[test]
    fn packet_header_to_vec() {
        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            forward_ip: Ipv4Addr::new(127, 0, 0, 1),
            forward_port: 8080,
        };

        let bytes: Vec<u8> = header.into();
        assert_eq!(bytes.len(), PacketHeader::LEN);
        assert_eq!(PacketHeader::from_bytes(&bytes), Some(header));
    }

    #[test]
    fn noeio_packet_to_vec() {
        let bytes = vec![1, 10, 0, 0, 8, 0xCA, 0x6C, 9, 8, 7];
        let packet = NoeioPacket::from(bytes.clone());

        let out: Vec<u8> = packet.into();
        assert_eq!(out, bytes);
    }
}
