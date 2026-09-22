use clap::Parser;
use noeio::cli::{Cli, Command, CreateResource};
use noeio::config::Config;
use noeio::daemon::NoeioDaemon;
use noeio::rpc::client::CliRpcClient;
use noeio::rpc::service;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
        Command::Boot {
            config,
            port,
            stun,
            derper_servers,
            derper_tokens,
        } => {
            let mut cfg = Config::load(config);
            cfg.append_stuns(stun);
            cfg.append_derpers(derper_servers, derper_tokens);

            let conn = UdpSocket::bind(format!("0.0.0.0:{}", port)).await.unwrap();
            let state = NoeioDaemon::new(conn, cfg).await;

            // Serve until a shutdown signal, then converge the system back to
            // its pre-boot state. This is the best-effort path (systemd stop,
            // ctrl_c); SIGKILL and panics skip it, which is why the start-up
            // sweep in the reconciler exists too.
            tokio::select! {
                res = service::run(state.clone()) => {
                    if let Err(err) = res {
                        tracing::error!("rpc service error: {}", err);
                    }
                }
                _ = wait_for_shutdown_signal() => {
                    tracing::info!("shutdown signal received, stopping noeio daemon");
                }
            }
            if tokio::time::timeout(Duration::from_secs(5), state.shutdown())
                .await
                .is_err()
            {
                tracing::warn!("timed out cleaning up routes on shutdown");
            }
        }
        Command::Create { resource } => {
            let mut client = CliRpcClient::new()
                .await
                .expect("failed to connect to daemon");
            match resource {
                CreateResource::Vnic {
                    ip,
                    ip_version,
                    network,
                } => client.create_vnic(ip, ip_version, network).await.unwrap(),
            }
        }
        Command::Netcheck => {
            let mut client = CliRpcClient::new()
                .await
                .expect("failed to connect to daemon");
            client.net_check().await.unwrap();
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
