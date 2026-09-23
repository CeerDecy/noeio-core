use moka::notification::RemovalCause;
use moka::sync::Cache;
use noeio_common::host_info::{HostInfo, NetworkId, PeerId};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::sync::mpsc;

const HEARTBEAT_TTL: Duration = Duration::from_mins(1);

/// A peer whose reports stopped: what we last knew about it. Broadcast to the
/// rest of its network as a tombstone so consumers drop the routes it
/// contributed — they cannot discover this themselves, because a dead peer
/// sends no withdrawal and a healthy one with stable config sends nothing
/// either (reports are deduplicated by `resource_version`).
#[derive(Debug, Clone)]
pub struct Gone {
    pub peer_id: PeerId,
    pub info: HostInfo,
    pub network: NetworkId,
}

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
    /// `gone` receives every peer the TTL expires. Expiry in moka is lazy —
    /// it happens on access or on [`Self::sweep`], so the owner must call
    /// `sweep` periodically for tombstones to be timely.
    pub fn new(trigger: Arc<Notify>, gone: mpsc::UnboundedSender<Gone>) -> Self {
        Self::with_ttl(trigger, gone, HEARTBEAT_TTL)
    }

    /// [`Self::new`] with an explicit liveness TTL (tests).
    pub fn with_ttl(
        trigger: Arc<Notify>,
        gone: mpsc::UnboundedSender<Gone>,
        ttl: Duration,
    ) -> Self {
        let peers = Cache::builder()
            .time_to_live(ttl)
            .eviction_listener(move |peer_id: Arc<PeerId>, value, cause| {
                // `Replaced` is the heartbeat re-insert; `Size` can't happen
                // (unbounded). Only a real disappearance is a tombstone.
                if !matches!(cause, RemovalCause::Expired | RemovalCause::Explicit) {
                    return;
                }
                let (_, info, network): (SocketAddr, HostInfo, NetworkId) = value;
                // A closed receiver means the derper is shutting down; the
                // listener must never panic, so the error is dropped.
                let _ = gone.send(Gone {
                    peer_id: *peer_id,
                    info,
                    network,
                });
            })
            .build();
        let by_addr = Cache::builder().time_to_live(ttl).build();
        PeerManager {
            peers,
            by_addr,
            trigger,
        }
    }

    /// Run moka's deferred maintenance so expired entries are actually
    /// removed (and their eviction listener fires) even when nobody touches
    /// them.
    pub fn sweep(&self) {
        self.peers.run_pending_tasks();
        self.by_addr.run_pending_tasks();
    }

    pub fn heartbeat(&self, peer_id: PeerId, info: HostInfo, addr: SocketAddr, network: NetworkId) {
        if let Some((prev_addr, prev_info, prev_network)) = self.peers.get(&peer_id) {
            // Reports are ordered by the HostInfo resource version.  A stale
            // or duplicate report must not roll the route back or trigger a
            // new SyncRoute broadcast.  Reinsert the current value so the
            // periodic report still refreshes the liveness TTL.
            if info.resource_version <= prev_info.resource_version {
                self.peers
                    .insert(peer_id, (prev_addr, prev_info, prev_network));
                self.by_addr.insert((prev_addr, prev_network), peer_id);
                return;
            }
        }

        let changed =
            self.peers
                .get(&peer_id)
                .is_none_or(|(prev_addr, prev_info, prev_network)| {
                    prev_addr != addr || prev_info != info || prev_network != network
                });
        self.peers.insert(peer_id, (addr, info.clone(), network));
        self.by_addr.insert((addr, network), peer_id);
        if changed {
            tracing::info!(
                "handle notify one for peer_id {}, host info {:?}",
                peer_id,
                info
            );
            self.trigger.notify_one();
        }
    }

    #[allow(dead_code)]
    pub fn is_alive(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<(SocketAddr, HostInfo, NetworkId)> {
        self.peers.get(peer_id)
    }

    #[allow(dead_code)]
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

    fn manager() -> (PeerManager, mpsc::UnboundedReceiver<Gone>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (PeerManager::new(Arc::new(Notify::new()), tx), rx)
    }

    #[test]
    fn resolves_sender_by_addr_scoped_to_network() {
        let (manager, _) = manager();
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
        let (manager, _) = manager();
        let net: NetworkId = [1u8; 16];
        manager.heartbeat(10, HostInfo::new(addr(1000)), addr(1000), net);
        // The peer re-registers from a new address; the old index entry
        // lingers until its TTL but must no longer attribute packets.
        manager.heartbeat(10, HostInfo::new(addr(2000)), addr(2000), net);

        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net), None);
        assert_eq!(manager.peer_id_by_addr(&addr(2000), &net), Some(10));
    }

    #[test]
    fn removed_peer_is_no_longer_resolvable_and_is_a_tombstone() {
        let (manager, mut gone) = manager();
        let net: NetworkId = [1u8; 16];
        manager.heartbeat(10, HostInfo::new(addr(1000)), addr(1000), net);
        manager.remove(&10);
        manager.sweep();

        assert_eq!(manager.peer_id_by_addr(&addr(1000), &net), None);
        let g = gone.try_recv().expect("explicit removal is a tombstone");
        assert_eq!(g.peer_id, 10);
        assert_eq!(g.network, net);
    }

    /// AC-6c, derper half: a peer whose reports stop is evicted by TTL and a
    /// tombstone carrying its last HostInfo (hence its advertised routes) is
    /// emitted; a peer that keeps reporting is not.
    #[test]
    fn ttl_expiry_emits_tombstone_with_last_host_info() {
        let (tx, mut gone) = mpsc::unbounded_channel();
        let manager = PeerManager::with_ttl(Arc::new(Notify::new()), tx, Duration::from_millis(50));
        let net: NetworkId = [1u8; 16];
        let mut info = HostInfo::new(addr(1000));
        info.hostname = "advertiser".into();
        manager.heartbeat(10, info, addr(1000), net);
        manager.heartbeat(20, HostInfo::new(addr(2000)), addr(2000), net);

        std::thread::sleep(Duration::from_millis(30));
        // Peer 20 keeps reporting; a dedup re-insert refreshes its TTL.
        manager.heartbeat(20, HostInfo::new(addr(2000)), addr(2000), net);
        std::thread::sleep(Duration::from_millis(30));
        manager.sweep();

        let g = gone.try_recv().expect("expired peer must be tombstoned");
        assert_eq!(g.peer_id, 10);
        assert_eq!(g.info.hostname, "advertiser");
        assert!(gone.try_recv().is_err(), "live peer must not be tombstoned");
        assert!(manager.is_alive(&20));
        assert!(!manager.is_alive(&10));
    }

    /// The heartbeat path re-inserts on every report; that is a `Replaced`,
    /// not a disappearance, and must not produce a tombstone.
    #[test]
    fn heartbeat_reinserts_do_not_tombstone() {
        let (manager, mut gone) = manager();
        let net: NetworkId = [1u8; 16];
        let mut info = HostInfo::new(addr(1000));
        info.resource_version = 1;
        manager.heartbeat(10, info.clone(), addr(1000), net);
        // duplicate (dedup path re-insert) and newer (changed path)
        manager.heartbeat(10, info.clone(), addr(1000), net);
        info.resource_version = 2;
        manager.heartbeat(10, info, addr(1000), net);
        manager.sweep();
        assert!(gone.try_recv().is_err());
    }

    #[test]
    fn stale_resource_version_does_not_replace_route() {
        let (manager, _) = manager();
        let net: NetworkId = [1u8; 16];
        let mut current = HostInfo::new(addr(1000));
        current.resource_version = 20;
        manager.heartbeat(10, current.clone(), addr(1000), net);

        let mut stale = HostInfo::new(addr(2000));
        stale.resource_version = 19;
        manager.heartbeat(10, stale, addr(2000), net);

        let (stored_addr, stored_info, stored_network) = manager.get(&10).unwrap();
        assert_eq!(stored_addr, addr(1000));
        assert_eq!(stored_info.resource_version, 20);
        assert_eq!(stored_network, net);
        assert_eq!(manager.peer_id_by_addr(&addr(2000), &net), None);
    }

    #[test]
    fn equal_resource_version_does_not_replace_route() {
        let (manager, _) = manager();
        let net: NetworkId = [1u8; 16];
        let mut current = HostInfo::new(addr(1000));
        current.resource_version = 20;
        manager.heartbeat(10, current.clone(), addr(1000), net);

        let mut duplicate = HostInfo::new(addr(2000));
        duplicate.resource_version = 20;
        manager.heartbeat(10, duplicate, addr(2000), net);

        let (stored_addr, stored_info, _) = manager.get(&10).unwrap();
        assert_eq!(stored_addr, addr(1000));
        assert_eq!(stored_info, current);
    }
}
