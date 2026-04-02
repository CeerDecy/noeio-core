mod delta;

use std::net::IpAddr;
use dashmap::DashMap;
use tokio::net::unix::SocketAddr;

type NatIPAddr = SocketAddr;
type VirtualIPAddr = SocketAddr;
pub struct NoeioRouter {
    vip_map: DashMap<IpAddr, NatIPAddr>
}

impl NoeioRouter {
    pub fn new() -> Self {
        NoeioRouter {
            vip_map: DashMap::new()
        }
    }
}
