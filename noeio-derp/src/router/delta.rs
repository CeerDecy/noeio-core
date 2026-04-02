use std::net::IpAddr;
use tokio::net::unix::SocketAddr;

#[derive(Debug, Clone)]
pub struct Delta {
    timestamp: u64,
    key: IpAddr,
    value: SocketAddr,
}
