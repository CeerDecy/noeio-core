use moka::sync::Cache;
use noeio_common::host_info::{HostInfo, NetworkId, PeerId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

const HEARTBEAT_TTL: Duration = Duration::from_mins(1);

#[derive(Debug, Clone)]
pub struct PeerManager {
    peers: Cache<PeerId, (SocketAddr, HostInfo, NetworkId)>,
    pub trigger: Arc<Notify>,
}

impl PeerManager {
    pub fn new(trigger: Arc<Notify>) -> Self {
        let peers = Cache::builder().time_to_live(HEARTBEAT_TTL).build();
        PeerManager { peers, trigger }
    }

    pub fn heartbeat(&self, peer_id: PeerId, info: HostInfo, addr: SocketAddr, network: NetworkId) {
        let changed =
            self.peers
                .get(&peer_id)
                .map_or(true, |(prev_addr, prev_info, prev_network)| {
                    prev_addr != addr || prev_info != info || prev_network != network
                });
        self.peers.insert(peer_id, (addr, info, network));
        if changed {
            self.trigger.notify_one();
        }
    }

    pub fn is_alive(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<(SocketAddr, HostInfo, NetworkId)> {
        self.peers.get(peer_id)
    }

    pub fn remove(&self, peer_id: &PeerId) {
        self.peers.invalidate(peer_id);
    }

    pub fn alive_peers(&self) -> Vec<(PeerId, (SocketAddr, HostInfo, NetworkId))> {
        self.peers.iter().map(|(k, v)| (*k, v)).collect()
    }
}
