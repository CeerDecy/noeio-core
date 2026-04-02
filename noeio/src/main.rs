use crate::cli::{Cli, Command};
use crate::pkg::stun;
use boringtun::noise::{Tunn, TunnResult};
use clap::Parser;
use interface::virtual_nic::VirtualNic;
use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tun::DeviceWriter;
use x25519_dalek::{PublicKey, StaticSecret};

mod cli;
mod common;
mod errors;
mod interface;
mod pkg;
mod tunnel;

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
            let conn = UdpSocket::bind("0.0.0.0:8000").await.unwrap();

            let mut local_private = StaticSecret::random();
            let local_public = PublicKey::from(&local_private);

            let mut tunn = Tunn::new(local_private, local_public, None, None, 1, None);

            let nic = VirtualNic::create().await;
            let (tun_writer, mut tun_reader) = nic.split().unwrap();

            let mut buf = vec![0u8; 4096];
            loop {
                let n = tun_reader.read(&mut buf).await.unwrap();

                let ipv4 = Ipv4Packet::new(&buf[4..n]).unwrap();
                println!("src {:?}", ipv4.get_source());
                println!("dst {:?}", ipv4.get_destination());

                if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                    println!("ICMP type: {:?}", icmp.get_icmp_type());
                }

                let mut wg_payload = vec![0u8; 8192];
                let result = tunn.encapsulate(&mut buf, &mut wg_payload);

                match result {
                    TunnResult::Done => {}
                    TunnResult::Err(err) => {
                        eprintln!("Error: {:?}", err);
                    }
                    TunnResult::WriteToNetwork(_) => {}
                    TunnResult::WriteToTunnelV4(_, _) => {}
                    TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
        }
        Command::Stun => {
            let factory = stun::StunClientFactory::new(Arc::new(
                UdpSocket::bind("0.0.0.0:8080").await.unwrap(),
            ));
            let mut client = factory.create().await.unwrap();
            if let Ok(addr) = client.get_address().await {
                println!("{}", addr);
            }
        }
        Command::OverlayTest => {
            let conn = UdpSocket::bind("0.0.0.0:8000").await.unwrap();
            let conn = Arc::new(conn);

            let nic = VirtualNic::create().await;

            let (tun_writer,mut tun_reader) = nic.split().unwrap();

            handle_udp_connection(tun_writer, conn.clone());
            keepalive(conn.clone());

            let mut buf = vec![0u8; 4096];
            loop {
                let n = tun_reader.read(&mut buf).await.unwrap();

                tracing::debug!("Received packet, sending to overlay, {:?}", buf);

                let header = PacketHeader {
                    packet_type: NoeioPacketType::Forward,
                    ip: Ipv4Addr::new(110, 0, 0, 1),
                    port: 8000,
                };
                let header_bytes = header.to_bytes();
                let mut payload = Vec::with_capacity(header_bytes.len() + n);
                payload.extend_from_slice(&header_bytes);
                payload.extend_from_slice(&buf[..n]);

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
                    let packet = NoeioPacket::from(payload);

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
                ip: Ipv4Addr::new(0, 0, 0, 0),
                port: 0,
            };
            let header_bytes = header.to_bytes();
            conn.send_to(
                header_bytes.as_slice(),
                "129.226.135.14:8080",
            )
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

