use crate::cli::{Cli, Command, TokenCommand};
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
mod config;
mod connection;
mod packet;
mod router;
mod rpc;
mod token;

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
        Command::Boot { port, config } => {
            let cfg = config::Config::load(config);
            tracing::info!(local = cfg.auth.local, "token auth configured");

            let auth = cfg.auth.clone();
            tokio::spawn(async move {
                if let Err(err) = rpc::service::run(auth).await {
                    tracing::error!("rpc service error: {}", err);
                }
            });

            let (sender, reader) = tokio::sync::broadcast::channel::<(SocketAddr, NoeioPacket)>(1);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            tracing::info!("Starting UDP server on 0.0.0.0:{}", port);
            let conn_manager = ConnectionManager::new(
                port,
                cfg.clone(),
                sender.clone(),
                reader,
                shutdown_rx.clone(),
            )
            .await;
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
        Command::Token { command } => match command {
            TokenCommand::Create { network, ttl, output } => {
                let ttl_seconds = match ttl {
                    None => None, // server default
                    Some(s) => match cli::parse_ttl(&s) {
                        Ok(d) => Some(d.as_secs()),
                        Err(err) => {
                            eprintln!("invalid --ttl: {}", err);
                            std::process::exit(1);
                        }
                    },
                };

                let mut client = match rpc::client::CliRpcClient::new().await {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("failed to connect to derper: {}\nHave you started the derper service?", err);
                        std::process::exit(1);
                    }
                };

                let resp = match client.create_token(network, ttl_seconds).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        eprintln!("failed to create token: {}", err);
                        std::process::exit(1);
                    }
                };

                if let Err(err) = cli::TokenOutput::from(&resp).print(output) {
                    eprintln!("failed to render output: {}", err);
                    std::process::exit(1);
                }
            }
            TokenCommand::Verify { token } => {
                let mut client = match rpc::client::CliRpcClient::new().await {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("failed to connect to derper: {}\nHave you started the derper service?", err);
                        std::process::exit(1);
                    }
                };

                let resp = match client.verify_token(token).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        eprintln!("failed to verify token: {}", err);
                        std::process::exit(1);
                    }
                };

                // Only colorize when stdout is a terminal so piped output
                // stays clean.
                use std::io::IsTerminal;
                let (green, red, reset) = if std::io::stdout().is_terminal() {
                    ("\x1b[32m", "\x1b[31m", "\x1b[0m")
                } else {
                    ("", "", "")
                };

                if resp.valid {
                    println!("valid: {green}true{reset}");
                } else {
                    println!("valid: {red}false{reset}");
                    println!("reason: {}", resp.reason.as_deref().unwrap_or("unknown"));
                    std::process::exit(1);
                }
            }
        },
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
