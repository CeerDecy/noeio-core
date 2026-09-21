use noeio_proto::proto::common::v1::{HostInfo as ProtoHostInfo, PeerInfo as ProtoPeerInfo};
use prost::Message;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub type PeerId = u32;
pub type NetworkId = [u8; 16];

fn nat_type_from_proto(value: u32) -> Result<NatType, std::io::Error> {
    let value = u8::try_from(value)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid nat type"))?;
    NatType::try_from(value)
}

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
    pub resource_version: u64,
    pub peer_id: PeerId,
    pub noeio_ip: IpAddr,
    pub network_id: NetworkId,
    pub nat_type: NatType,
    /// STUN-observed public address of the peer, if it has been probed. Used
    /// to open a direct UDP connection for NAT hole punching.
    pub nat_addr: Option<SocketAddr>,
    /// Addresses of the peer's physical NICs (LAN paths), each paired with its
    /// daemon's UDP port. Broadcast alongside `nat_addr` so other peers can
    /// open a tunnel session per candidate and pick the lowest-RTT path.
    pub local_addrs: Vec<SocketAddr>,
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, vip: IpAddr, network: &str) -> Result<Self, uuid::Error> {
        let network_id = Uuid::parse_str(network)?.into_bytes();
        Ok(Self {
            resource_version: 0,
            peer_id,
            noeio_ip: vip,
            network_id,
            nat_type: NatType::default(),
            nat_addr: None,
            local_addrs: Vec::new(),
        })
    }

    pub fn with_resource_version(mut self, resource_version: u64) -> Self {
        self.resource_version = resource_version;
        self
    }

    pub fn with_nat_type(mut self, nat_type: NatType) -> Self {
        self.nat_type = nat_type;
        self
    }

    pub fn with_nat_addr(mut self, nat_addr: Option<SocketAddr>) -> Self {
        self.nat_addr = nat_addr;
        self
    }

    pub fn with_local_addrs(mut self, local_addrs: Vec<SocketAddr>) -> Self {
        self.local_addrs = local_addrs;
        self
    }
}

/// Join socket addresses with `|` for the wire (an address never contains a
/// `|`, `,`, `;`, or `\r\n`, so it nests safely in every layer of the format).
fn join_addrs(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("|")
}

/// Parse a `|`-joined address list; empty input means no addresses.
fn parse_addrs(s: &str) -> Result<Vec<SocketAddr>, std::io::Error> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split('|')
        .map(|a| {
            a.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
        .collect()
}

impl From<&PeerInfo> for String {
    fn from(peer: &PeerInfo) -> Self {
        let nat_addr = peer
            .nat_addr
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        format!(
            "{},{},{},{},{},{},{}",
            peer.peer_id,
            peer.noeio_ip,
            Uuid::from_bytes(peer.network_id).hyphenated(),
            peer.nat_type,
            nat_addr,
            join_addrs(&peer.local_addrs),
            peer.resource_version
        )
    }
}

impl From<&PeerInfo> for Vec<u8> {
    fn from(peer: &PeerInfo) -> Self {
        ProtoPeerInfo::from(peer).encode_to_vec()
    }
}

impl TryFrom<&str> for PeerInfo {
    type Error = std::io::Error;

    fn try_from(entry: &str) -> Result<Self, Self::Error> {
        let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer entry");
        let mut fields = entry.splitn(7, ',');
        let peer_id_str = fields.next().ok_or_else(invalid)?;
        let vip_str = fields.next().ok_or_else(invalid)?;
        let network_str = fields.next().ok_or_else(invalid)?;
        let nat_type_str = fields.next().ok_or_else(invalid)?;
        let nat_addr_str = fields.next().ok_or_else(invalid)?;
        // Optional trailing field: a sender that predates local-address
        // reporting emits five fields, which parses as "no LAN candidates".
        let local_addrs_str = fields.next().unwrap_or("");
        let resource_version: u64 = fields
            .next()
            .unwrap_or("0")
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

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
        let local_addrs = parse_addrs(local_addrs_str)?;
        PeerInfo::new(peer_id, vip, network_str)
            .map(|peer| {
                peer.with_resource_version(resource_version)
                    .with_nat_type(nat_type)
                    .with_nat_addr(nat_addr)
                    .with_local_addrs(local_addrs)
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl TryFrom<&[u8]> for PeerInfo {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(proto) = ProtoPeerInfo::decode(data)
            && let Ok(peer) = Self::try_from(proto)
        {
            return Ok(peer);
        }

        let s = std::str::from_utf8(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        PeerInfo::try_from(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub resource_version: u64,
    pub nat_addr: SocketAddr,
    pub nat_type: NatType,
    pub hostname: String,
    /// Deprecated: LAN candidates now travel on each [`PeerInfo`]
    /// (`PeerInfo::local_addrs`), the per-network identity the derper
    /// actually broadcasts. This host-level copy is retained for legacy
    /// payload parsing and older peers.
    pub local_addrs: Vec<SocketAddr>,
    pub peers: Vec<PeerInfo>,
}

impl HostInfo {
    pub fn new(nat_addr: SocketAddr) -> Self {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        Self {
            resource_version: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            nat_addr,
            nat_type: NatType::default(),
            hostname,
            local_addrs: Vec::new(),
            peers: Vec::new(),
        }
    }

    pub fn with_networks(mut self, networks: Vec<PeerInfo>) -> Self {
        self.peers = networks;
        self
    }

    pub fn with_local_addrs(mut self, local_addrs: Vec<SocketAddr>) -> Self {
        self.local_addrs = local_addrs;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let proto = ProtoHostInfo {
            resource_version: self.resource_version,
            nat_addr: self.nat_addr.to_string(),
            nat_type: u8::from(self.nat_type) as u32,
            hostname: self.hostname.clone(),
            local_addrs: self.local_addrs.iter().map(ToString::to_string).collect(),
            peers: self.peers.iter().map(ProtoPeerInfo::from).collect(),
        };
        proto.encode_to_vec()
    }
}

impl From<&PeerInfo> for ProtoPeerInfo {
    fn from(peer: &PeerInfo) -> Self {
        Self {
            resource_version: peer.resource_version,
            peer_id: peer.peer_id,
            noeio_ip: match peer.noeio_ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            },
            network_id: peer.network_id.to_vec(),
            nat_type: u8::from(peer.nat_type) as u32,
            nat_addr: peer
                .nat_addr
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            local_addrs: peer.local_addrs.iter().map(ToString::to_string).collect(),
        }
    }
}

impl TryFrom<&[u8]> for HostInfo {
    type Error = std::io::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(proto) = ProtoHostInfo::decode(data)
            && let Ok(info) = Self::try_from_proto(proto)
        {
            return Ok(info);
        }
        Self::try_from_legacy(data)
    }
}

impl HostInfo {
    fn try_from_proto(proto: ProtoHostInfo) -> Result<Self, std::io::Error> {
        let nat_addr = proto
            .nat_addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let nat_type = nat_type_from_proto(proto.nat_type)?;
        let local_addrs = proto
            .local_addrs
            .iter()
            .map(|addr| {
                addr.parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
            .collect::<Result<Vec<SocketAddr>, _>>()?;
        let peers = proto
            .peers
            .into_iter()
            .map(PeerInfo::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            resource_version: proto.resource_version,
            nat_addr,
            nat_type,
            hostname: proto.hostname,
            local_addrs,
            peers,
        })
    }

    fn try_from_legacy(data: &[u8]) -> Result<Self, std::io::Error> {
        let s = std::str::from_utf8(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut parts = s.splitn(6, "\r\n");
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
        // Optional trailing segment (see `to_bytes`): absent in legacy
        // payloads, which predate local-address reporting.
        let local_addrs_str = parts.next().unwrap_or("");
        let resource_version: u64 = parts
            .next()
            .unwrap_or("0")
            .trim()
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let nat_addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let nat_type: NatType = nat_type_str.parse()?;

        let local_addrs = parse_addrs(local_addrs_str)?;

        let networks = if networks_str.is_empty() {
            Vec::new()
        } else {
            networks_str
                .split(';')
                .map(PeerInfo::try_from)
                .collect::<Result<Vec<_>, std::io::Error>>()?
        };

        Ok(HostInfo {
            resource_version,
            nat_addr,
            nat_type,
            hostname,
            local_addrs,
            peers: networks,
        })
    }
}

impl TryFrom<ProtoPeerInfo> for PeerInfo {
    type Error = std::io::Error;

    fn try_from(proto: ProtoPeerInfo) -> Result<Self, Self::Error> {
        let noeio_ip = match proto.noeio_ip.as_slice() {
            [a, b, c, d] => IpAddr::from([*a, *b, *c, *d]),
            bytes if bytes.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                IpAddr::from(octets)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid noeio ip",
                ));
            }
        };
        if proto.network_id.len() != 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid network id",
            ));
        }
        let mut network_id = [0u8; 16];
        network_id.copy_from_slice(&proto.network_id);
        let nat_addr = if proto.nat_addr.is_empty() {
            None
        } else {
            Some(
                proto
                    .nat_addr
                    .parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            )
        };
        let local_addrs = proto
            .local_addrs
            .iter()
            .map(|addr| {
                addr.parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
            .collect::<Result<Vec<SocketAddr>, _>>()?;
        Ok(Self {
            resource_version: proto.resource_version,
            peer_id: proto.peer_id,
            noeio_ip,
            network_id,
            nat_type: nat_type_from_proto(proto.nat_type)?,
            nat_addr,
            local_addrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
            PeerInfo::new(
                new_peer_id(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                SAMPLE_NET_A,
            )
            .unwrap(),
            PeerInfo::new(
                new_peer_id(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                SAMPLE_NET_B,
            )
            .unwrap(),
        ];
        let info = HostInfo::new(sample_addr()).with_networks(nets.clone());
        assert_eq!(info.peers.len(), 2);
        assert_eq!(info.peers[0].peer_id, nets[0].peer_id);
        assert_eq!(
            info.peers[1].noeio_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn to_bytes_and_try_from_roundtrip() {
        let nets = vec![
            PeerInfo::new(
                new_peer_id(),
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                SAMPLE_NET_A,
            )
            .unwrap()
            .with_nat_type(NatType::Symmetric),
            PeerInfo::new(
                new_peer_id(),
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                SAMPLE_NET_B,
            )
            .unwrap(),
        ];
        let info = HostInfo {
            resource_version: 1,
            nat_addr: sample_addr(),
            nat_type: NatType::Symmetric,
            hostname: "example-host".to_string(),
            local_addrs: vec!["192.168.1.10:41641".parse().unwrap()],
            peers: nets,
        };

        let bytes = info.to_bytes();
        let parsed = HostInfo::try_from(bytes.as_slice()).unwrap();

        assert_eq!(parsed.nat_addr, info.nat_addr);
        assert_eq!(parsed.nat_type, info.nat_type);
        assert_eq!(parsed.hostname, info.hostname);
        assert_eq!(parsed.resource_version, info.resource_version);
        assert_eq!(parsed.local_addrs, info.local_addrs);
        assert_eq!(parsed.peers.len(), info.peers.len());
        for (a, b) in parsed.peers.iter().zip(info.peers.iter()) {
            assert_eq!(a.peer_id, b.peer_id);
            assert_eq!(a.noeio_ip, b.noeio_ip);
            assert_eq!(a.network_id, b.network_id);
            assert_eq!(a.nat_type, b.nat_type);
            assert_eq!(a.resource_version, b.resource_version);
        }
    }

    #[test]
    fn to_bytes_with_empty_networks() {
        let info = HostInfo {
            resource_version: 1,
            nat_addr: sample_addr(),
            nat_type: NatType::Other,
            hostname: "h".to_string(),
            local_addrs: Vec::new(),
            peers: Vec::new(),
        };
        let bytes = info.to_bytes();
        let parsed = HostInfo::try_from(bytes.as_slice()).unwrap();
        assert!(parsed.peers.is_empty());
        assert_eq!(parsed.hostname, "h");
        assert_eq!(parsed.resource_version, 1);
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
        let data =
            b"203.0.113.5:51820\r\n1\r\nhost\r\n1,not-an-ip,550e8400-e29b-41d4-a716-446655440000,1";
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
    fn try_from_rejects_invalid_local_addrs() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost\r\n\r\nnot-an-addr";
        let err = HostInfo::try_from(data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn try_from_accepts_missing_networks_section() {
        let data = b"203.0.113.5:51820\r\n1\r\nhost";
        let parsed = HostInfo::try_from(data.as_slice()).unwrap();
        assert_eq!(parsed.hostname, "host");
        assert!(parsed.local_addrs.is_empty());
        assert!(parsed.peers.is_empty());
    }

    #[test]
    fn try_from_accepts_legacy_payload_without_local_addrs() {
        // A legacy sender emits four segments with the peer list last; the
        // upgraded parser must keep accepting it (local_addrs empty).
        let data = b"203.0.113.5:51820\r\n1\r\nhost\r\n42,10.64.0.2,550e8400-e29b-41d4-a716-446655440000,1,203.0.113.5:51820";
        let parsed = HostInfo::try_from(data.as_slice()).unwrap();
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].peer_id, 42);
        assert!(parsed.local_addrs.is_empty());
    }

    #[test]
    fn host_info_roundtrips_local_addrs() {
        let info = HostInfo {
            resource_version: 1,
            nat_addr: sample_addr(),
            nat_type: NatType::Other,
            hostname: "h".to_string(),
            local_addrs: vec![
                "192.168.1.10:41641".parse().unwrap(),
                "10.10.0.3:41641".parse().unwrap(),
            ],
            peers: Vec::new(),
        };
        let parsed = HostInfo::try_from(info.to_bytes().as_slice()).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn peer_info_roundtrips_local_addrs() {
        let info = PeerInfo::new(42, IpAddr::V4(Ipv4Addr::new(10, 64, 0, 2)), SAMPLE_NET_A)
            .unwrap()
            .with_resource_version(7)
            .with_nat_addr(Some(sample_addr()))
            .with_local_addrs(vec![
                "192.168.1.10:41641".parse().unwrap(),
                "10.10.0.3:41641".parse().unwrap(),
            ]);
        let wire = String::from(&info);
        let parsed = PeerInfo::try_from(wire.as_str()).unwrap();
        assert_eq!(parsed, info);

        let protobuf_wire: Vec<u8> = (&info).into();
        let parsed = PeerInfo::try_from(protobuf_wire.as_slice()).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn peer_info_parses_legacy_five_field_entry() {
        // A sender that predates local-address reporting emits five fields;
        // that must still parse, with no LAN candidates.
        let entry = "42,10.64.0.2,550e8400-e29b-41d4-a716-446655440000,1,203.0.113.5:51820";
        let parsed = PeerInfo::try_from(entry).unwrap();
        assert_eq!(parsed.peer_id, 42);
        assert_eq!(parsed.nat_addr, Some(sample_addr()));
        assert!(parsed.local_addrs.is_empty());
    }
}
