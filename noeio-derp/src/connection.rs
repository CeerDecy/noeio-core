use crate::config::Config;
use crate::connection::peer::PeerManager;
use crate::token;
use noeio_common::host_info::NetworkId;
use noeio_common::packet::report::ReportPayload;
use noeio_common::packet::{
    MAX_PACKET_LEN, NoeioPacket, NoeioPacketType, PacketHeader, PingPacketPayload,
};
use uuid::Uuid;
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
    config: Config,
}

impl ConnectionManager {
    pub async fn new(
        port: u16,
        config: Config,
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
            config,
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
        let config = self.config.clone();
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
                        // A Forward is addressed *to us*: its peer_id names the
                        // destination peer. Before relaying we rewrite it into a
                        // Delivery stamped with the *sender's* peer id, so the
                        // receiver can resolve the sending peer (e.g. to pick
                        // the right tunnel session) and knows not to re-forward.
                        let header = match packet.parse_header() {
                            None => {
                                tracing::error!("invalid header {:?}", packet.inner);
                                continue;
                            }
                            Some(header) => header,
                        };

                        let (target_addr, _, target_network) = match manager.get(&header.peer_id) {
                            None => {
                                tracing::error!("no peer found {}", &header.peer_id);
                                continue;
                            }
                            Some(entry) => entry,
                        };

                        // The sender's identity comes from our own peer table
                        // (fed by token-verified Reports), not from anything the
                        // sender claims in the packet, so it can't be spoofed by
                        // another network member.
                        let Some(sender_id) = manager.peer_id_by_addr(&addr, &target_network)
                        else {
                            tracing::warn!(
                                source = %addr,
                                target = header.peer_id,
                                "dropping forward from unregistered sender"
                            );
                            continue;
                        };

                        let mut packet = packet;
                        packet.set_header(PacketHeader {
                            packet_type: NoeioPacketType::Delivery,
                            peer_id: sender_id,
                            port: header.port,
                        });

                        if let Err(err) = udp.send_to(&packet.inner, target_addr).await {
                            tracing::error!("failed to send packet: {}", err);
                        }
                    }
                    NoeioPacketType::SyncRoute => {}
                    NoeioPacketType::Delivery => {
                        // Delivery is the relay's *output*, addressed to a final
                        // receiver; one arriving here is misrouted. Never relay
                        // it (that would let a sender forge the sender stamp).
                        tracing::warn!(source = %addr, "dropping delivery packet sent to relay");
                    }
                    NoeioPacketType::Seq
                    | NoeioPacketType::Ack
                    | NoeioPacketType::TunnelPing
                    | NoeioPacketType::TunnelPong => {
                        // Hole-punch and ping/pong signalling is peer-to-peer;
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

                        let report = match ReportPayload::try_from(payload) {
                            Ok(report) => report,
                            Err(err) => {
                                tracing::warn!(source = %addr, "invalid report payload: {}", err);
                                continue;
                            }
                        };

                        // Reject reports whose token doesn't verify. No reply
                        // is sent: probers learn nothing.
                        let claims = match token::verify(&config.auth.secret, &report.token) {
                            Ok(claims) => claims,
                            Err(err) => {
                                tracing::warn!(source = %addr, "rejected report: {}", err);
                                continue;
                            }
                        };

                        // The token is scoped to one network (`sub`); peers
                        // reported outside it are dropped.
                        let token_network: NetworkId = match Uuid::parse_str(&claims.sub) {
                            Ok(uuid) => uuid.into_bytes(),
                            Err(err) => {
                                tracing::warn!(
                                    source = %addr,
                                    sub = %claims.sub,
                                    "rejected report: token sub is not a network uuid: {}",
                                    err
                                );
                                continue;
                            }
                        };

                        let host_info = report.host_info;
                        tracing::info!(
                            "received a report from {} peer_id={} {:?}",
                            addr,
                            header.peer_id,
                            host_info
                        );

                        for info in &host_info.peers {
                            if info.network_id != token_network {
                                tracing::warn!(
                                    source = %addr,
                                    peer = %info.peer_id,
                                    "dropping reported peer outside the token's network"
                                );
                                continue;
                            }

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
                            // Stamp the host-level path candidates into the
                            // broadcast entry: the STUN address and the LAN
                            // addresses. Receivers open a session per
                            // candidate and pick by RTT. LAN candidates come
                            // from the peer entry itself; the host-level list
                            // is a fallback for senders that predate per-peer
                            // local_addrs (HostInfo.local_addrs is deprecated).
                            let local_addrs = if peer_info.local_addrs.is_empty() {
                                info.local_addrs.clone()
                            } else {
                                peer_info.local_addrs.clone()
                            };
                            let info = peer_info
                                .clone()
                                .with_nat_type(info.nat_type)
                                .with_nat_addr(Some(info.nat_addr))
                                .with_local_addrs(local_addrs);
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
    // `recv_from` silently truncates datagrams longer than the buffer; a
    // truncated ciphertext relayed onward would just fail decryption at the
    // receiver, so drop it here where the cause is still visible. Can't
    // happen while nodes keep NIC_MTU well below this size.
    if data.len() >= MAX_PACKET_LEN {
        return Err(format!(
            "dropping datagram from {}: fills the {}-byte buffer, likely truncated",
            addr, MAX_PACKET_LEN
        )
        .into());
    }

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
