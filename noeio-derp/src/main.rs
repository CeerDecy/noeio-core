use crate::cli::{Cli, Command};
use crate::connection::ConnectionManager;
use crate::packet::PacketManager;
use clap::Parser;
use noeio_common::packet::NoeioPacket;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod cli;
mod connection;
mod packet;
mod router;

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
        Command::Boot { port } => {
            let (sender, reader) = tokio::sync::broadcast::channel::<(SocketAddr, NoeioPacket)>(1);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            tracing::info!("Starting UDP server on 0.0.0.0:{}", port);
            let conn_manager =
                ConnectionManager::new(port, sender.clone(), reader, shutdown_rx.clone()).await;
            // let packet_manager = PacketManager::new(sender.clone(), shutdown_rx);

            wait_for_shutdown_signal().await;
            tracing::info!("Shutdown signal received, stopping DERP server");

            let _ = shutdown_tx.send(true);
            drop(sender);

            if tokio::time::timeout(Duration::from_secs(3), conn_manager.shutdown())
                .await
                .is_err()
            {
                tracing::warn!("Timed out waiting for connection manager to stop");
            }

            // if tokio::time::timeout(Duration::from_secs(3), packet_manager.shutdown())
            //     .await
            //     .is_err()
            // {
            //     tracing::warn!("Timed out waiting for packet manager to stop");
            // }
        }
    }
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
