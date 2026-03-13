use crate::connection::peer::PeerManager;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use noeio_common::packet::NoeioPacket;

mod peer;
mod udp;

pub struct ConnectionConfig {
    port: u16,
}

struct ConnectionManager {
    peer_manager: PeerManager,
    socket: Arc<UdpSocket>,

    task: JoinSet<()>,
}

impl ConnectionManager {
    pub async fn new(cfg: ConnectionConfig) -> Self {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", cfg.port)).await.unwrap();
        let udp = Arc::new(socket);
        let task: JoinSet<()> = JoinSet::new();

        let mut manager = ConnectionManager {
            peer_manager: PeerManager::new(),
            socket: udp,
            task,
        };

        manager.handle_connect();

        manager
    }

    pub fn handle_connect(&mut self) {
        let udp = Arc::clone(&self.socket);
        self.task.spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let (n, from_addr) = match udp.recv_from(&mut buf).await {
                    Ok(package_info) => package_info,
                    Err(err) => {
                        tracing::error!(%err, "udp recv error");
                        continue;
                    }
                };
                let packet = NoeioPacket::from(buf.clone());
                
            }
        });
    }
}
