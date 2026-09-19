use clap::Parser;
use noeio::cli::{Cli, Command, CreateResource};
use noeio::config::Config;
use noeio::daemon::NoeioDaemon;
use noeio::rpc::client::CliRpcClient;
use noeio::rpc::service;
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
        Command::Boot { config, port } => {
            let cfg = Config::load(config);

            let conn = UdpSocket::bind(format!("0.0.0.0:{}", port)).await.unwrap();
            let state = NoeioDaemon::new(conn, cfg).await;

            service::run(state).await.expect("TODO: panic message");
        }
        Command::Create { resource } => {
            let mut client = CliRpcClient::new()
                .await
                .expect("failed to connect to daemon");
            match resource {
                CreateResource::Network {
                    name,
                    ip,
                    ip_version,
                    cidr,
                } => client
                    .create_network(name, ip, ip_version, cidr)
                    .await
                    .unwrap(),
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
