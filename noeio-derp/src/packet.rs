use noeio_common::packet::NoeioPacket;
use std::net::SocketAddr;
use tokio::sync::broadcast::Sender;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub struct PacketManager {
    pub sender: Sender<(SocketAddr, NoeioPacket)>,
    pub shutdown: watch::Receiver<bool>,
    pub task: JoinSet<()>,
}

impl PacketManager {
    pub fn new(sender: Sender<(SocketAddr, NoeioPacket)>, shutdown: watch::Receiver<bool>) -> Self {
        let task: JoinSet<()> = JoinSet::new();

        let mut manager = PacketManager {
            sender,
            shutdown,
            task,
        };

        manager.handle_recv();

        manager
    }

    pub fn handle_recv(&mut self) {
        let mut receiver = self.sender.subscribe();
        let mut shutdown = self.shutdown.clone();
        self.task.spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            tracing::info!("packet manager received shutdown signal");
                            break;
                        }
                    }
                    recv_result = receiver.recv() => {
                        let (addr, payload) = match recv_result {
                            Ok(packet) => packet,
                            Err(err) => {
                                tracing::error!("failed to receive packet: {}", err);
                                continue;
                            }
                        };

                        tracing::info!("received packet: {:?}", payload);

                        if let Some(header) = payload.parse_header() {
                            tracing::info!("parsed header: {:?}", header);
                        }
                    }
                }
            }
        });
    }

    pub async fn shutdown(mut self) {
        while let Some(result) = self.task.join_next().await {
            if let Err(err) = result {
                tracing::error!("packet manager task join error: {}", err);
            }
        }
    }
}
