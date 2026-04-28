pub mod derper;
pub mod nic;
pub mod stun;

use crate::common;
use crate::config::Config;
use crate::daemon::derper::DerperManager;
use crate::daemon::nic::NicManager;
use crate::daemon::stun::StunManager;
use crate::interface::virtual_nic::VirtualNic;
use bytecodec::{DecodeExt, EncodeExt, Error as BytecodecError};
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use noeio_common::host_info;
use noeio_common::host_info::{HostInfo, PeerId, PeerInfo};
use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use smoltcp::wire::Ipv4Packet;
use std::convert::Infallible;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use stun_codec::rfc5389::Attribute;
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::ChangeRequest;
use stun_codec::{Message, MessageDecoder, MessageEncoder};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tun::DeviceReader;

const MAX_BUFFER_SIZE: usize = 2048;

pub struct NoeioDaemon {
    pub nics: NicManager,
    pub udp: UdpSocket,
    pub config: Config,
    pub derper: DerperManager,
    pub stun: StunManager,
    pub host_info: Mutex<Option<HostInfo>>,
    pub router: DashMap<IpAddr, PeerId>,
    pub task: JoinSet<()>,
}

impl NoeioDaemon {
    pub fn new(udp: UdpSocket, cfg: Config) -> Arc<Self> {
        let derper = DerperManager::from(cfg.derper.clone());
        let stun = StunManager::from(cfg.stun.clone());
        let daemon = Arc::new(Self {
            nics: NicManager::new(),
            udp,
            derper,
            stun,
            config: cfg,
            host_info: Mutex::new(None),
            router: DashMap::new(),
            task: JoinSet::new(),
        });

        process_inbound(daemon.clone());

        stun_probe(daemon.clone());

        register_host_info(daemon.clone());
        daemon
    }

    pub async fn add_peer(&self, peer: host_info::PeerInfo) -> Result<(), &'static str> {
        let mut info = self.host_info.lock().await;
        match info.as_mut() {
            Some(host) => {
                if let Some(existing) = host.peers.iter_mut().find(|p| p.noeio_ip == peer.noeio_ip)
                {
                    existing.peer_id = peer.peer_id;
                } else {
                    host.peers.push(peer);
                }
                Ok(())
            }
            None => Err("host info not initialized"),
        }
    }

    pub async fn register_nic(
        &self,
        state: Arc<NoeioDaemon>,
        nic: VirtualNic,
        reader: DeviceReader,
        network: String,
    ) -> Result<(), String> {
        let peer_id = host_info::new_peer_id();
        let peer = host_info::PeerInfo::new(peer_id, nic.ip, &network)
            .map_err(|err| format!("failed to create peer: {}", err))?;

        tracing::info!(peer_id = %peer_id, "creating virtual nic {}", nic.ip);

        self.nics.register(peer_id, nic);
        self.add_peer(peer).await?;
        process_outbound(state, reader);
        Ok(())
    }
}

pub fn process_outbound(state: Arc<NoeioDaemon>, mut reader: DeviceReader) {
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_BUFFER_SIZE];
        loop {
            match reader.read(&mut buf).await {
                Ok(n) => {
                    // TODO: macOS utun prefixes every packet with 4 bytes of
                    // protocol family (AF_INET = 2). Strip it here so the rest
                    // of the pipeline sees raw IPv4. Move this into a NicReader
                    // wrapper once the bug is confirmed end-to-end.
                    #[cfg(target_os = "macos")]
                    let ip_bytes: &[u8] = if n >= 4 { &buf[4..n] } else { continue };
                    #[cfg(not(target_os = "macos"))]
                    let ip_bytes: &[u8] = &buf[..n];

                    tracing::debug!("received outbound packet: {:?}", ip_bytes);

                    if let Some(ipv4) = Ipv4Packet::new_checked(ip_bytes).ok() {
                        let dst_ip = IpAddr::from(ipv4.dst_addr());

                        let peer_id = match state.router.get(&dst_ip) {
                            None => {
                                tracing::error!(
                                    "no router found for {}, {:?}",
                                    dst_ip,
                                    state.router
                                );
                                continue;
                            }
                            Some(peer) => peer.clone(),
                        };

                        let header = PacketHeader {
                            packet_type: NoeioPacketType::Forward,
                            peer_id,
                            port: 0,
                        };

                        let header_bytes = header.to_bytes();
                        let mut payload = Vec::with_capacity(header_bytes.len() + ip_bytes.len());
                        payload.extend_from_slice(&header_bytes);
                        payload.extend_from_slice(ip_bytes);

                        let derper = match state.derper.current().await {
                            None => {
                                tracing::error!("DERPER: No server selected");
                                continue;
                            }
                            Some(derper) => derper,
                        };

                        if let Err(err) = state.udp.send_to(&payload, derper).await {
                            tracing::error!("Failed to send packet: {}", err);
                        }
                    }
                }
                Err(err) => {
                    eprintln!("err: {}", err);
                }
            }
        }
    });
}

fn register_host_info(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(core::time::Duration::from_secs(10)).await;

            if let Some(derper_addr) = daemon.derper.current().await
                && let Some(host_info) = daemon.host_info.lock().await.clone()
            {
                let addr = match derper_addr.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(err) => {
                        tracing::error!("failed to parse derper address: {}", err);
                        continue;
                    }
                };

                let payload = host_info.to_bytes();
                let mut header = PacketHeader::default();

                if daemon.nics.peers().len() <= 0 {
                    tracing::warn!("no nic found");
                    continue;
                }

                // TODO
                let peer_id = daemon.nics.peers()[0];

                tracing::info!(peer = %peer_id, "peer id");

                header.packet_type = NoeioPacketType::Report;
                header.peer_id = peer_id;

                let header_bytes = header.to_bytes();
                let mut packet = Vec::with_capacity(header_bytes.len() + payload.len());
                packet.extend_from_slice(&header_bytes);
                packet.extend_from_slice(&payload);

                if let Err(err) = daemon.udp.send_to(&packet, addr).await {
                    tracing::error!("failed to send host info: {}", err);
                }
                tracing::info!("host info sent to {}", addr);
            } else {
                tracing::error!("failed to parse host_info");
            }
        }
    });
}

pub fn stun_probe(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        loop {
            if let Some(stun_server) = daemon.stun.pick_server() {
                let addrs: Vec<_> = match lookup_host(stun_server).await {
                    Ok(addr) => addr.collect(),
                    Err(err) => {
                        tracing::error!("stun server lookup failed: {}", err);
                        return;
                    }
                };

                let server_addr = match addrs
                    .iter()
                    .copied()
                    .find(|addr| addr.is_ipv4())
                    .or_else(|| addrs.first().copied())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "failed to resolve STUN server")
                    }) {
                    Ok(addr) => addr,
                    Err(err) => {
                        tracing::error!("stun server lookup failed: {}", err);
                        return;
                    }
                };

                let tid = common::stun::generate_tid();
                let message: stun_codec::Message<ChangeRequest> =
                    stun_codec::Message::new(stun_codec::MessageClass::Request, BINDING, tid);

                let mut encoder = MessageEncoder::new();
                let bytes = encoder.encode_into_bytes(message).unwrap();

                daemon.udp.send_to(&bytes, server_addr).await.unwrap();
            }

            tokio::time::sleep(std::time::Duration::from_mins(10)).await;
        }
    });
}

pub fn process_inbound(state: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_BUFFER_SIZE];
        loop {
            match state.udp.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    if let Ok(packet) = NoeioPacket::try_from(&buf[..n])
                        && let Some(header) = packet.parse_header()
                    {
                        match header.packet_type {
                            NoeioPacketType::Ping => {}
                            NoeioPacketType::Forward => {
                                if let Some(mut nic) = state.nics.get_mut(&header.peer_id) {
                                    let mut data = vec![];
                                    if let Some(payload) = packet.payload() {
                                        data = payload.to_vec();
                                    }

                                    tracing::info!("ready to send packet: {:?}", &data);

                                    // TODO: macOS utun requires a 4-byte AF_INET prefix on
                                    // writes; the tun crate (0.8.6) doesn't prepend it for us.
                                    // Move this into a VirtualNic wrapper once the bug is
                                    // confirmed end-to-end.
                                    #[cfg(target_os = "macos")]
                                    let data = {
                                        let mut framed = Vec::with_capacity(4 + data.len());
                                        framed.extend_from_slice(&[0, 0, 0, 2]); // AF_INET, big-endian
                                        framed.extend_from_slice(&data);
                                        framed
                                    };

                                    if let Err(err) = nic.writer.write(data.as_slice()).await {
                                        tracing::error!(
                                            "Failed to write to {} nic: {}",
                                            header.peer_id,
                                            err
                                        );
                                        continue;
                                    }

                                    tracing::info!("sent packet to {}", header.peer_id);
                                } else {
                                    tracing::error!("can't get nic for peer {}", header.peer_id);
                                }
                            }
                            NoeioPacketType::SyncRoute => {
                                if let Some(payload) = packet.payload() {
                                    match PeerInfo::try_from(payload) {
                                        Ok(peer) => {
                                            state.router.insert(peer.noeio_ip, peer.peer_id);
                                            if let Err(err) =
                                                state.nics.route(Some(header.peer_id), peer.noeio_ip).await
                                            {
                                                tracing::error!(
                                                    "Failed to route peer {} via local nic {}: {}",
                                                    peer.noeio_ip,
                                                    header.peer_id,
                                                    err
                                                );
                                            }
                                        }
                                        Err(err) => {
                                            tracing::error!(
                                                "failed to parse SyncRoute payload: {}",
                                                err
                                            );
                                        }
                                    };
                                }
                            }
                            NoeioPacketType::Report => {}
                        }
                        continue;
                    }

                    // Handle STUN response
                    let mut decoder = MessageDecoder::<Attribute>::new();
                    if let Ok(response) = decoder.decode_from_bytes(&buf[..n]) {
                        let response = response.map_err(BytecodecError::from).unwrap();

                        let addr = parse_mapped_addr(response)
                            .ok_or_else(|| "failed to parse mapped address".to_string())
                            .unwrap();

                        {
                            let mut info = state.host_info.lock().await;
                            let new_info = HostInfo::new(addr);
                            match info.as_mut() {
                                Some(existing) => {
                                    existing.nat_addr = new_info.nat_addr;
                                    existing.hostname = new_info.hostname;
                                }
                                None => {
                                    *info = Some(new_info);
                                }
                            }
                        }
                        tracing::info!("Received NAT address: {} from stun server", addr);
                        continue;
                    }

                    tracing::info!("unsupported packet: {:?}", &buf[..n]);
                }
                Err(err) => {
                    tracing::error!("UDP recv error: {}", err);
                }
            }
        }
    });
}

fn parse_mapped_addr(response: Message<Attribute>) -> Option<SocketAddr> {
    for attr in response.attributes() {
        match attr {
            Attribute::MappedAddress(address) => return Some(address.address()),
            Attribute::XorMappedAddress(address) => return Some(address.address()),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use noeio_common::host_info::{HostInfo, PeerInfo, new_peer_id};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const SAMPLE_NET: &str = "550e8400-e29b-41d4-a716-446655440000";

    async fn test_daemon(host_info: Option<HostInfo>) -> NoeioDaemon {
        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        NoeioDaemon {
            nics: NicManager::new(),
            udp,
            config: Config::default(),
            derper: DerperManager::from(crate::config::Derper::default()),
            stun: StunManager::from(crate::config::Stun::default()),
            host_info: Mutex::new(host_info),
            router: DashMap::new(),
            task: JoinSet::new(),
        }
    }

    #[tokio::test]
    async fn add_peer_returns_err_when_host_info_is_none() {
        let daemon = test_daemon(None).await;
        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        assert!(daemon.add_peer(peer).await.is_err());
    }

    #[tokio::test]
    async fn add_peer_pushes_new_peer() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        let peer_clone = peer.clone();
        daemon.add_peer(peer).await.unwrap();

        let info = daemon.host_info.lock().await;
        let peers = &info.as_ref().unwrap().peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].noeio_ip, peer_clone.noeio_ip);
        assert_eq!(peers[0].peer_id, peer_clone.peer_id);
    }

    #[tokio::test]
    async fn add_peer_updates_existing_peer_id_by_ip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let old_id = new_peer_id();
        let new_id = new_peer_id();

        daemon
            .add_peer(PeerInfo::new(old_id, ip, SAMPLE_NET).unwrap())
            .await
            .unwrap();
        daemon
            .add_peer(PeerInfo::new(new_id, ip, SAMPLE_NET).unwrap())
            .await
            .unwrap();

        let info = daemon.host_info.lock().await;
        let peers = &info.as_ref().unwrap().peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, new_id);
    }

    #[tokio::test]
    async fn add_peer_different_ips_both_kept() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let p1 = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        let p2 = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            SAMPLE_NET,
        )
        .unwrap();
        daemon.add_peer(p1).await.unwrap();
        daemon.add_peer(p2).await.unwrap();

        let info = daemon.host_info.lock().await;
        assert_eq!(info.as_ref().unwrap().peers.len(), 2);
    }
}
