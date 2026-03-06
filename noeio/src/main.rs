use crate::cli::{Cli, Command};
use crate::pkg::stun;
use boringtun::noise::{Tunn, TunnResult};
use clap::Parser;
use interface::virtual_nic::VirtualNic;
use pnet::packet::Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use std::io::Read;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
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

            let nic = VirtualNic::new().await;

            let mut buf = vec![0u8; 4096];
            loop {
                let n = {
                    let mut tun_lock = nic.tun.lock().await;
                    tun_lock.read(&mut buf).unwrap()
                };

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
    }
}
