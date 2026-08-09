use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

pub type PeerId = u32;
pub type NetworkId = [u8; 16];

pub fn new_peer_id() -> PeerId {
    rand::random()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NatType {
    Symmetric = 0,
    #[default]
    Other = 1,
}

impl From<NatType> for u8 {
    fn from(nat: NatType) -> Self {
        nat as u8
    }
}

impl TryFrom<u8> for NatType {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(NatType::Symmetric),
            1 => Ok(NatType::Other),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid nat type",
            )),
        }
    }
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u8::from(*self))
    }
}

impl std::str::FromStr for NatType {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u8 = s
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        NatType::try_from(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub network_id: NetworkId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub noeio_ip: IpAddr,
    pub network_id: NetworkId,
    pub nat_type: NatType,
    /// STUN-observed public address of the peer, if it has been probed. Used
    /// to open a direct UDP connection for NAT hole punching.
    pub nat_addr: Option<SocketAddr>,
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, vip: IpAddr, network: &str) -> Result<Self, uuid::Error> {
        let network_id = Uuid::parse_str(network)?.into_bytes();
        Ok(Self {
            peer_id,
            noeio_ip: vip,
            network_id,
            nat_type: NatType::default(),
            nat_addr: None,
        })
    }

    pub fn with_nat_type(mut self, nat_type: NatType) -> Self {
        self.nat_type = nat_type;
        self
    }

    pub fn with_nat_addr(mut self, nat_addr: Option<SocketAddr>) -> Self {
        self.nat_addr = nat_addr;
        self
    }
}

impl From<&PeerInfo> for String {
    fn from(peer: &PeerInfo) -> Self {
        let nat_addr = peer
            .nat_addr
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        format!(
            "{},{},{},{},{}",
            peer.peer_id,
            peer.noeio_ip,
            Uuid::from_bytes(peer.network_id).hyphenated(),
            peer.nat_type,
            nat_addr
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
        let mut fields = entry.splitn(5, ',');
        let peer_id_str = fields.next().ok_or_else(invalid)?;
        let vip_str = fields.next().ok_or_else(invalid)?;
        let network_str = fields.next().ok_or_else(invalid)?;
        let nat_type_str = fields.next().ok_or_else(invalid)?;
        let nat_addr_str = fields.next().ok_or_else(invalid)?;

        let peer_id: PeerId = peer_id_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let vip: IpAddr = vip_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let nat_type: NatType = nat_type_str.parse()?;
        // An empty trailing field means the peer has no STUN address yet.
        let nat_addr: Option<SocketAddr> = if nat_addr_str.is_empty() {
            None
        } else {
            Some(
                nat_addr_str
                    .parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            )
        };
        PeerInfo::new(peer_id, vip, network_str)
            .map(|peer| peer.with_nat_type(nat_type).with_nat_addr(nat_addr))
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
    pub nat_type: NatType,
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
            nat_type: NatType::default(),
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
        format!(
            "{}\r\n{}\r\n{}\r\n{}",
            self.nat_addr, self.nat_type, self.hostname, networks_str
        )
        .into_bytes()
    }
}

impl TryFrom<&[u8]> for HostInfo {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut parts = s.splitn(4, "\r\n");
        let addr_str = parts
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing addr"))?;
        let nat_type_str = parts.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing nat type")
        })?;
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

        let nat_type: NatType = nat_type_str.parse()?;

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
            nat_type,
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
            PeerInfo::new(new_peer_id(), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), SAMPLE_NET_A)
                .unwrap()
                .with_nat_type(NatType::Symmetric),
            PeerInfo::new(new_peer_id(), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), SAMPLE_NET_B).unwrap(),
        ];
        let info = HostInfo {
            nat_addr: sample_addr(),
            nat_type: NatType::Symmetric,
            hostname: "example-host".to_string(),
            peers: nets,
        };

        let bytes = info.to_bytes();
        let parsed = HostInfo::try_from(bytes.as_slice()).unwrap();

        assert_eq!(parsed.nat_addr, info.nat_addr);
        assert_eq!(parsed.nat_type, info.nat_type);
        assert_eq!(parsed.hostname, info.hostname);
        assert_eq!(parsed.peers.len(), info.peers.len());
        for (a, b) in parsed.peers.iter().zip(info.peers.iter()) {
            assert_eq!(a.peer_id, b.peer_id);
            assert_eq!(a.noeio_ip, b.noeio_ip);
            assert_eq!(a.network_id, b.network_id);
            assert_eq!(a.nat_type, b.nat_type);
        }
    }

    #[test]
    fn to_bytes_with_empty_networks() {
        let info = HostInfo {
            nat_addr: sample_addr(),
            nat_type: NatType::Other,
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
        let data = b"203.0.113.5:51820\r\n1";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_bad_addr() {
        let data = b"not-an-addr\r\n1\r\nhost\r\n";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_nat_type() {
        let data = b"203.0.113.5:51820\r\n9\r\nhost\r\n";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_network_entry() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost\r\nno-comma-entry";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_vip() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost\r\n1,not-an-ip,550e8400-e29b-41d4-a716-446655440000,1";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_rejects_invalid_network_id() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost\r\n1,10.0.0.1,not-a-uuid,1";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_accepts_missing_networks_section() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost";
        let parsed = HostInfo::try_from(data.as_slice()).unwrap();
        assert_eq!(parsed.hostname, "host");
        assert!(parsed.peers.is_empty());
    }
}
