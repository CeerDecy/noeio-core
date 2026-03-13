use crate::cli::{Cli, Command};
use crate::packet::PacketManager;
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::Sender;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod cli;
mod connection;
mod packet;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    match cli.command {
        Command::Boot => {
            let (sender, _) = tokio::sync::broadcast::channel::<Vec<u8>>(1);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            tracing::info!("Starting UDP server on 0.0.0.0:8080");
            let socket = UdpSocket::bind("0.0.0.0:8080").await.unwrap();
            let udp = Arc::new(socket);

            let udp_task = handle_udp_connection(udp.clone(), sender.clone(), shutdown_rx.clone());
            let packet_manager = PacketManager::new(sender.clone(), shutdown_rx);

            wait_for_shutdown_signal().await;
            tracing::info!("Shutdown signal received, stopping DERP server");

            let _ = shutdown_tx.send(true);
            drop(sender);

            match tokio::time::timeout(Duration::from_secs(3), udp_task).await {
                Err(_) => tracing::warn!("Timed out waiting for UDP task to stop"),
                Ok(Err(err)) => tracing::error!("UDP task join error: {}", err),
                Ok(Ok(())) => {}
            }

            if tokio::time::timeout(Duration::from_secs(3), packet_manager.shutdown())
                .await
                .is_err()
            {
                tracing::warn!("Timed out waiting for packet manager to stop");
            }
        }
    }
}

fn handle_udp_connection(
    udp: Arc<UdpSocket>,
    sender: Sender<Vec<u8>>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0; 2048];
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("udp listener received shutdown signal");
                        break;
                    }
                }
                recv_result = udp.recv_from(&mut buf) => {
                    let (size, _) = match recv_result {
                        Ok(v) => v,
                        Err(err) => {
                            tracing::error!("failed to receive udp packet: {}", err);
                            continue;
                        }
                    };
                    let data = buf[..size].to_vec();
                    if let Err(err) = sender.send(data) {
                        if *shutdown.borrow() {
                            break;
                        }
                        tracing::error!("Error sending data: {:?}", err);
                    }
                }
            }
        }
    })
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!("failed to register SIGTERM handler: {}", err);
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
