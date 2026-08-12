use boringtun::noise::{Tunn, TunnResult};
use clap::Parser;
use noeio::cli::{Cli, Command, CreateResource, ListResource};
use noeio::config::Config;
use noeio::daemon::NoeioDaemon;
use noeio::interface::virtual_nic::VirtualNic;
use noeio::pkg::stun;
use noeio::rpc::client::CliRpcClient;
use noeio::rpc::service;
use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tun::DeviceWriter;
use x25519_dalek::{PublicKey, StaticSecret};

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
            let state = NoeioDaemon::new(conn, cfg);

            service::run(state).await.expect("TODO: panic message");
        }
        Command::Stun => {
            let factory = stun::StunClientFactory::new(Arc::new(
                UdpSocket::bind("0.0.0.0:8080").await.unwrap(),
            ));
            let mut client = factory.create("").await.unwrap();
            if let Ok(addr) = client.get_address().await {
                println!("{}", addr);
            }
        }
        Command::List { resource } => {
            let mut client = CliRpcClient::new()
                .await
                .expect("failed to connect to daemon");
            match resource {
                ListResource::Network => client.list_networks().await.unwrap(),
                ListResource::Vnic => client.list_vnics().await.unwrap(),
            }
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
        Command::OverlayTest => {
            let conn = UdpSocket::bind("0.0.0.0:8000").await.unwrap();
            let conn = Arc::new(conn);

            let (nic, mut tun_reader) =
                VirtualNic::create_ipv4_nic(Ipv4Addr::new(127, 0, 0, 1)).await;

            let tun_writer = nic.writer;

            handle_udp_connection(tun_writer, conn.clone());
            keepalive(conn.clone());

            let mut buf = vec![0u8; 4096];
            loop {
                let n = tun_reader.read(&mut buf).await.unwrap();

                tracing::debug!("Received packet, sending to overlay, {:?}", buf);

                let header = PacketHeader {
                    packet_type: NoeioPacketType::Forward,
                    peer_id: 0,
                    port: 8000,
                };
                let payload: Vec<u8> = NoeioPacket::new(header, &buf[..n]).into();

                tracing::debug!("payload: {:?}", payload);

                if let Err(err) = conn.send_to(&payload, "129.226.135.14:8080").await {
                    tracing::error!(%err, "overlay test send error");
                }
            }
        }
    }
}

fn handle_udp_connection(mut writer: DeviceWriter, conn: Arc<UdpSocket>) {
    tokio::spawn(async move {
        loop {
            let mut buf = vec![0u8; 4096];
            match conn.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    tracing::info!(
                        "Received packet from {}, sending to overlay, {:?}",
                        addr,
                        &buf[0..n]
                    );

                    let payload = buf[..n].to_vec();
                    let packet = match NoeioPacket::try_from(payload) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("invalid packet from {}: {}", addr, e);
                            continue;
                        }
                    };

                    let mut data = vec![];
                    if let Some(payload) = packet.payload() {
                        data = payload.to_vec()
                    }

                    writer.write(&data).await.unwrap();
                }
                Err(err) => {
                    tracing::error!(%err, "Error receiving data");
                }
            }
        }
    });
}

fn keepalive(conn: Arc<UdpSocket>) {
    tokio::spawn(async move {
        loop {
            let header = PacketHeader {
                packet_type: NoeioPacketType::Ping,
                peer_id: 0,
                port: 0,
            };
            let bytes: Vec<u8> = NoeioPacket::new(header, &[]).into();
            conn.send_to(bytes.as_slice(), "129.226.135.14:8080")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}
