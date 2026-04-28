use std::sync::Arc;
use tokio::net::{ToSocketAddrs, UdpSocket};
use crate::interface::virtual_nic::VirtualNic;

pub struct WireguardTunnel {
    udp_socket: Arc<UdpSocket>,
}

impl WireguardTunnel {
    pub async fn new<A: ToSocketAddrs>(addr: A) -> Self {
        let socket = UdpSocket::bind(addr).await.unwrap();
        WireguardTunnel {
            udp_socket: Arc::new(socket),
        }
    }

    pub async fn start(&mut self) {
        // let nic = VirtualNic::create_ipv4_nic().await;

    }
}


