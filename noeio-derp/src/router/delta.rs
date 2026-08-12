use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Delta {
    timestamp: u64,
    key: IpAddr,
    value: SocketAddr,
}
