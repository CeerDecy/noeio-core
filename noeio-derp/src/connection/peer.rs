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
    /// Reverse index for the relay hot path: which peer registered this
    /// transport address within a network. Kept on the same TTL as `peers`,
    /// but only a hint — entries can go stale for up to a TTL after a peer
    /// re-registers elsewhere, so lookups verify against `peers` before use.
    by_addr: Cache<(SocketAddr, NetworkId), PeerId>,
    pub trigger: Arc<Notify>,
}

impl PeerManager {
    pub fn new(trigger: Arc<Notify>) -> Self {
        let peers = Cache::builder().time_to_live(HEARTBEAT_TTL).build();
        let by_addr = Cache::builder().time_to_live(HEARTBEAT_TTL).build();
        PeerManager {
            peers,
            by_addr,
            trigger,
        }
    }

    pub fn heartbeat(&self, peer_id: PeerId, info: HostInfo, addr: SocketAddr, network: NetworkId) {
        let changed =
            self.peers
                .get(&peer_id)
                .map_or(true, |(prev_addr, prev_info, prev_network)| {
                    prev_addr != addr || prev_info != info || prev_network != network
                });
        self.peers.insert(peer_id, (addr, info, network));
        self.by_addr.insert((addr, network), peer_id);
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
        if let Some((addr, _, network)) = self.peers.get(peer_id) {
            self.by_addr.invalidate(&(addr, network));
        }
        self.peers.invalidate(peer_id);
    }

    pub fn alive_peers(&self) -> Vec<(PeerId, (SocketAddr, HostInfo, NetworkId))> {
        self.peers.iter().map(|(k, v)| (*k, v)).collect()
    }

    /// Resolve which peer a datagram came from: the peer registered (via an
    /// authenticated Report) with this transport address inside `network`.
    ///
    /// One host address can map to several peer ids (one per network it has
    /// joined), so the caller must scope the lookup to the network it is
    /// relaying within.
    ///
    /// O(1): served from the `by_addr` index, then confirmed against the
    /// authoritative `peers` table so a stale index entry (the peer has since
    /// re-registered at another address) can never mis-attribute a packet.
    pub fn peer_id_by_addr(&self, addr: &SocketAddr, network: &NetworkId) -> Option<PeerId> {
        let peer_id = self.by_addr.get(&(*addr, *network))?;
        let (current_addr, _, current_network) = self.peers.get(&peer_id)?;
        (current_addr == *addr && current_network == *network).then_some(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("192.0.2.1:{port}").parse().unwrap()
    }

    fn manager() -> PeerManager {
        PeerManager::new(Arc::new(Notify::new()))
    }

    #[test]
    fn resolves_sender_by_addr_scoped_to_network() {
        let manager = manager();
        let net_a: NetworkId = [1u8; 16];
        let net_b: NetworkId = [2u8; 16];
        // The same host address holds one peer id per network it joined.
        manager.heartbeat(10, HostInfo::new(addr(1000)), addr(1000), net_a);
        manager.heartbeat(20, HostInfo::new(addr(1000)), addr(1000), net_b);

        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net_a), Some(10));
        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net_b), Some(20));
        assert_eq!(manager.peer_id_by_addr(&addr(2000), &net_a), None);
    }

    #[test]
    fn stale_index_entry_is_rejected_after_peer_moves() {
        let manager = manager();
        let net: NetworkId = [1u8; 16];
        manager.heartbeat(10, HostInfo::new(addr(1000)), addr(1000), net);
        // The peer re-registers from a new address; the old index entry
        // lingers until its TTL but must no longer attribute packets.
        manager.heartbeat(10, HostInfo::new(addr(2000)), addr(2000), net);

        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net), None);
        assert_eq!(manager.peer_id_by_addr(&addr(2000), &net), Some(10));
    }

    #[test]
    fn removed_peer_is_no_longer_resolvable() {
        let manager = manager();
        let net: NetworkId = [1u8; 16];
        manager.heartbeat(10, HostInfo::new(addr(1000)), addr(1000), net);
        manager.remove(&10);

        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net), None);
    }
}
