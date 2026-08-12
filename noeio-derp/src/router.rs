mod delta;

use std::net::{IpAddr, SocketAddr};
use dashmap::DashMap;

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
