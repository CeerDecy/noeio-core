use crate::connection::peer::PeerManager;
use noeio_common::host_info::HostInfo;
use noeio_common::packet::{
    MAX_PACKET_LEN, NoeioPacket, NoeioPacketType, PacketHeader, PingPacketPayload,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub mod peer;
mod udp;

pub struct ConnectionManager {
    peer_manager: Arc<PeerManager>,
    socket: Arc<UdpSocket>,
    sender: Sender<(SocketAddr, NoeioPacket)>,
    shutdown: watch::Receiver<bool>,
    task: JoinSet<()>,
}

impl ConnectionManager {
    pub async fn new(
        port: u16,
        sender: Sender<(SocketAddr, NoeioPacket)>,
        reader: Receiver<(SocketAddr, NoeioPacket)>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await.unwrap();
        let udp = Arc::new(socket);
        let task: JoinSet<()> = JoinSet::new();

        let trigger = Arc::new(Notify::new());

        let mut manager = ConnectionManager {
            peer_manager: Arc::new(PeerManager::new(trigger.clone())),
            socket: udp,
            sender,
            shutdown,
            task,
        };

        manager.handle_connect();
        manager.handle_packet_recv(reader);
        manager.handle_sync(trigger);

        manager
    }

    fn handle_connect(&mut self) {
        let udp = Arc::clone(&self.socket);
        let sender = self.sender.clone();
        let mut shutdown = self.shutdown.clone();
        self.task.spawn(async move {
            let mut buf = [0; MAX_PACKET_LEN];
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            tracing::info!("udp listener received shutdown signal");
                            break;
                        }
                    }
                    recv_result = udp.recv_from(&mut buf) => {
                        let (size, addr) = match recv_result {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::error!("failed to receive udp packet: {}", err);
                                continue;
                            }
                        };

                        tracing::debug!("recv content from {}", addr);

                        if let Err(err) = handle_udp_recv(&buf[..size], addr, &sender).await {
                            tracing::error!("Error handling UDP recv: {}", err);
                        }
                    }
                }
            }
        });
    }

    pub async fn shutdown(mut self) {
        while let Some(result) = self.task.join_next().await {
            if let Err(err) = result {
                tracing::error!("connection manager task join error: {}", err);
            }
        }
    }

    fn handle_packet_recv(&mut self, mut reader: Receiver<(SocketAddr, NoeioPacket)>) {
        let manager = self.peer_manager.clone();
        let udp = self.socket.clone();
        self.task.spawn(async move {
            loop {
                let (addr, packet) = match reader.recv().await {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::error!("failed to receive packet: {}", err);
                        continue;
                    }
                };

                tracing::debug!("handle received packet from {}", addr);

                match packet.packet_type {
                    NoeioPacketType::Ping => {}
                    NoeioPacketType::Forward => {
                        let header = match packet.parse_header() {
                            None => {
                                tracing::error!("invalid header {:?}", packet.inner);
                                continue;
                            }
                            Some(header) => header,
                        };

                        match manager.get(&header.peer_id) {
                            None => {
                                tracing::error!("no peer found {}", &header.peer_id);
                                continue;
                            }
                            Some((addr, _, _)) => {
                                let payload = packet.inner.to_vec();
                                if let Err(err) = udp.send_to(&payload, addr).await {
                                    tracing::error!("failed to send packet: {}", err);
                                }
                            }
                        }
                    }
                    NoeioPacketType::SyncRoute => {}
                    NoeioPacketType::Seq
                    | NoeioPacketType::Ack
                    | NoeioPacketType::KeepAlive => {
                        // Hole-punch and keepalive signalling is peer-to-peer;
                        // the relay does not act on it.
                    }
                    NoeioPacketType::Report => {
                        let header = match packet.parse_header() {
                            None => {
                                tracing::error!("invalid report header {:?}", packet.inner);
                                continue;
                            }
                            Some(header) => header,
                        };

                        let payload = match packet.payload() {
                            None => {
                                tracing::warn!(
                                    "packet payload received but no payload could be found"
                                );
                                continue;
                            }
                            Some(payload) => payload,
                        };

                        if let Ok(host_info) = HostInfo::try_from(payload) {
                            tracing::info!(
                                "received a sync route from {} peer_id={} {:?}",
                                addr,
                                header.peer_id,
                                host_info
                            );

                            for info in &host_info.peers {
                                manager.heartbeat(
                                    info.peer_id,
                                    host_info.clone(),
                                    addr,
                                    info.network_id,
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    fn handle_sync(&mut self, trigger: Arc<Notify>) {
        let manager = self.peer_manager.clone();
        let udp = self.socket.clone();

        self.task.spawn(async move {
            loop {
                trigger.notified().await;

                let peers = manager.alive_peers();
                for (target_id, (addr, _, target_network)) in &peers {
                    for (peer_id, (_, info, network)) in &peers {
                        if target_id == peer_id {
                            tracing::info!(target_id = ?target_id, peer_id = %peer_id, "skip sync route, peer id is same: {:?}", &info);
                            continue;
                        }
                        if target_network != network {
                            tracing::info!(network_id = ?network,peer_id = %peer_id, "skip sync route, not in same network: {:?}", &info);
                            continue;
                        }

                        let info = info.clone();

                        for peer_info in info.peers {
                            if &peer_info.peer_id == target_id {
                                tracing::info!(info_id = %peer_info.peer_id, peer_id = %target_id, "skip sync route, peer id is same in PeerInfo: {:?}", peer_info);
                                continue;
                            }

                            let udp = udp.clone();
                            let to_addr = addr.clone();
                            let info = peer_info
                                .clone()
                                .with_nat_type(info.nat_type)
                                .with_nat_addr(Some(info.nat_addr));
                            let payload: Vec<u8> = (&info).into();
                            let target_peer = target_id.clone();
                            tokio::spawn(async move {
                                let mut header = PacketHeader::default();
                                header.packet_type = NoeioPacketType::SyncRoute;
                                header.peer_id = target_peer;

                                let packet: Vec<u8> = NoeioPacket::new(header, &payload).into();

                                if let Err(err) = udp.send_to(packet.as_slice(), to_addr).await {
                                    tracing::error!("failed to send sync route: {}", err);
                                }
                                tracing::info!(target_peer = %target_peer, "sent sync route to {}, peer info {:?}", to_addr,info);
                            });
                        }
                    }
                }
            }
        });
    }
}

async fn handle_udp_recv(
    data: &[u8],
    addr: SocketAddr,
    sender: &Sender<(SocketAddr, NoeioPacket)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = data.to_vec();
    let mut packet = NoeioPacket::try_from(data)?;

    if let Some(header) = packet.parse_header() {
        tracing::debug!("received udp packet: {:?}", header);
    }

    if packet.packet_type == NoeioPacketType::Ping {
        let ipv4_addr = match to_ipv4(addr) {
            None => return Err(format!("[handle ping] Address {} is not IPv4", addr).into()),
            Some(ip) => ip,
        };
        let payload = PingPacketPayload {
            ip: ipv4_addr,
            port: addr.port(),
        };
        packet.set_payload(&payload.to_bytes());
    }

    // if packet.packet_type == NoeioPacketType::Report {
    //     let ipv4_addr = match to_ipv4(addr) {
    //         None => return Err(format!("[handle ping] Address {} is not IPv4", addr).into()),
    //         Some(ip) => ip,
    //     };
    //     packet.set_header(PacketHeader {
    //         packet_type: NoeioPacketType::Report,
    //         peer_id: 0, // TODO: resolve peer_id from connection addr
    //         port: addr.port(),
    //     })
    // }

    if let Err(err) = sender.send((addr, packet)) {
        tracing::error!("Error sending data: {:?}", err);
    }
    Ok(())
}

fn to_ipv4(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
