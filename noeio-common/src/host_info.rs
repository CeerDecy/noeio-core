use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

pub type PeerId = u32;
pub type NetworkId = [u8; 16];

pub fn new_peer_id() -> PeerId {
    rand::random()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub noeio_ip: IpAddr,
    pub network_id: NetworkId,
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, vip: IpAddr, network: &str) -> Result<Self, uuid::Error> {
        let network_id = Uuid::parse_str(network)?.into_bytes();
        Ok(Self {
            peer_id,
            noeio_ip: vip,
            network_id,
        })
    }
}

impl From<&PeerInfo> for String {
    fn from(peer: &PeerInfo) -> Self {
        format!(
            "{},{},{}",
            peer.peer_id,
            peer.noeio_ip,
            Uuid::from_bytes(peer.network_id).hyphenated()
        )
    }
}

impl From<&PeerInfo> for Vec<u8> {
    fn from(peer: &PeerInfo) -> Self {
        String::from(peer).into_bytes()
    }
}

impl TryFrom<&str> for PeerInfo {
    type Error = std::io::Error;

    fn try_from(entry: &str) -> Result<Self, Self::Error> {
        let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer entry");
        let mut fields = entry.splitn(3, ',');
        let peer_id_str = fields.next().ok_or_else(invalid)?;
        let vip_str = fields.next().ok_or_else(invalid)?;
        let network_str = fields.next().ok_or_else(invalid)?;

        let peer_id: PeerId = peer_id_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let vip: IpAddr = vip_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        PeerInfo::new(peer_id, vip, network_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl TryFrom<&[u8]> for PeerInfo {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        PeerInfo::try_from(s)
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub nat_addr: SocketAddr,
    pub hostname: String,
    pub peers: Vec<PeerInfo>,
}

impl HostInfo {
    pub fn new(nat_addr: SocketAddr) -> Self {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        Self {
            nat_addr,
            hostname,
            peers: Vec::new(),
        }
    }

    pub fn with_networks(mut self, networks: Vec<PeerInfo>) -> Self {
        self.peers = networks;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: replace this ad-hoc text format with a binary encoding (protobuf / bincode)
        // once the field set stabilizes — the `\r\n` / `;` / `,` layering will not scale.
        let networks_str: String = self
            .peers
            .iter()
            .map(String::from)
            .collect::<Vec<_>>()
            .join(";");
        format!("{}\r\n{}\r\n{}", self.nat_addr, self.hostname, networks_str).into_bytes()
    }
}

impl TryFrom<&[u8]> for HostInfo {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut parts = s.splitn(3, "\r\n");
        let addr_str = parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing addr"))?;
        let hostname = parts
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing hostname")
            })?
            .to_string();
        let networks_str = parts.next().unwrap_or("");

        let nat_addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let networks = if networks_str.is_empty() {
            Vec::new()
        } else {
            networks_str
                .split(';')
                .map(PeerInfo::try_from)
                .collect::<Result<Vec<_>, std::io::Error>>()?
        };

        Ok(HostInfo {
            nat_addr,
            hostname,
            peers: networks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, Ipv6Addr};

    fn sample_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 51820)
    }

    const SAMPLE_NET_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SAMPLE_NET_B: &str = "00000000-0000-0000-0000-000000000001";

    #[test]
    fn new_sets_addr_and_empty_networks() {
        let info = HostInfo::new(sample_addr());
        assert_eq!(info.nat_addr, sample_addr());
        assert!(info.peers.is_empty());
        assert!(!info.hostname.is_empty() || info.hostname.is_empty());
    }

    #[test]
    fn with_networks_replaces_networks() {
        let nets = vec![
            PeerInfo::new(new_peer_id(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), SAMPLE_NET_A).unwrap(),
            PeerInfo::new(new_peer_id(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), SAMPLE_NET_B).unwrap(),
        ];
        let info = HostInfo::new(sample_addr()).with_networks(nets.clone());
        assert_eq!(info.peers.len(), 2);
        assert_eq!(info.peers[0].peer_id, nets[0].peer_id);
        assert_eq!(info.peers[1].noeio_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn to_bytes_and_try_from_roundtrip() {
        let nets = vec![
            PeerInfo::new(new_peer_id(), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), SAMPLE_NET_A).unwrap(),
            PeerInfo::new(new_peer_id(), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), SAMPLE_NET_B).unwrap(),
        ];
        let info = HostInfo {
            nat_addr: sample_addr(),
            hostname: "example-host".to_string(),
            peers: nets,
        };

        let bytes = info.to_bytes();
        let parsed = HostInfo::try_from(bytes.as_slice()).unwrap();

        assert_eq!(parsed.nat_addr, info.nat_addr);
        assert_eq!(parsed.hostname, info.hostname);
        assert_eq!(parsed.peers.len(), info.peers.len());
        for (a, b) in parsed.peers.iter().zip(info.peers.iter()) {
            assert_eq!(a.peer_id, b.peer_id);
            assert_eq!(a.noeio_ip, b.noeio_ip);
            assert_eq!(a.network_id, b.network_id);
        }
    }

    #[test]
    fn to_bytes_with_empty_networks() {
        let info = HostInfo {
            nat_addr: sample_addr(),
            hostname: "h".to_string(),
            peers: Vec::new(),
        };
        let bytes = info.to_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.ends_with("\r\n"));

        let parsed = HostInfo::try_from(bytes.as_slice()).unwrap();
        assert!(parsed.peers.is_empty());
        assert_eq!(parsed.hostname, "h");
    }

    #[test]
    fn try_from_rejects_non_utf8() {
        let data = vec![0xFF, 0xFE, 0xFD];
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_missing_hostname() {
        let data = b"203.0.113.5:51820";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_bad_addr() {
        let data = b"not-an-addr\r\nhost\r\n";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_network_entry() {
        let data = b"203.0.113.5:51820\r\nhost\r\nno-comma-entry";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_vip() {
        let data = b"203.0.113.5:51820\r\nhost\r\n1,not-an-ip,550e8400-e29b-41d4-a716-446655440000";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_network_id() {
        let data = b"203.0.113.5:51820\r\nhost\r\n1,10.0.0.1,not-a-uuid";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_accepts_missing_networks_section() {
        let data = b"203.0.113.5:51820\r\nhost";
        let parsed = HostInfo::try_from(data.as_slice()).unwrap();
        assert_eq!(parsed.hostname, "host");
        assert!(parsed.peers.is_empty());
    }
}
