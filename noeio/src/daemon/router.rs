use crate::daemon::peer::Peer;
use dashmap::DashMap;
use noeio_common::host_info::{PeerId, PeerInfo};
use std::net::IpAddr;
use std::sync::Arc;

/// Concurrent routing table of known peers.
///
/// Peers are stored once, keyed by their virtual IP ([`IpAddr`]). A secondary
/// index maps each peer's [`PeerId`] to that virtual IP, so a peer can be looked
/// up by either key without duplicating the [`Peer`] itself.
///
/// Entries are `Arc<Peer>` and lookups clone the `Arc` out, so no shard guard
/// ever escapes this module — callers can hold a peer across `.await` freely.
/// Peers mutate through interior mutability (`&self`), so there is no `get_mut`.
#[derive(Default)]
pub struct Router {
    /// Primary store: virtual IP -> peer.
    peers: DashMap<IpAddr, Arc<Peer>>,
    /// Secondary index: peer id -> virtual IP.
    by_peer_id: DashMap<PeerId, IpAddr>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a peer, keeping the `PeerId` index in sync.
    ///
    /// If a peer already occupied this virtual IP under a different `PeerId`,
    /// that stale index entry is removed so it can't resolve to the wrong IP.
    pub fn insert(&self, peer: Arc<Peer>) {
        let info = peer.info();
        if let Some(old) = self.peers.insert(info.noeio_ip, peer) {
            let old_peer_id = old.info().peer_id;
            if old_peer_id != info.peer_id {
                self.by_peer_id.remove(&old_peer_id);
            }
        }
        self.by_peer_id.insert(info.peer_id, info.noeio_ip);
    }

    /// Refresh an existing peer's identity in place, keeping the `PeerId`
    /// index in sync.
    ///
    /// A peer that re-registers keeps its virtual IP but may arrive under a new
    /// `PeerId`, so the primary store needs no change while the secondary index
    /// does: the old entry would otherwise resolve forever and the new id would
    /// never resolve at all. Mutating the peer directly leaves that index
    /// stale, which is why identity updates belong here rather than on [`Peer`].
    pub fn update_info(&self, peer: &Peer, info: PeerInfo, local_peer_id: PeerId) {
        let old_peer_id = peer.info().peer_id;
        let (new_peer_id, ip) = (info.peer_id, info.noeio_ip);
        peer.update_info(info, local_peer_id);
        if old_peer_id != new_peer_id {
            self.by_peer_id.remove(&old_peer_id);
        }
        self.by_peer_id.insert(new_peer_id, ip);
    }

    /// Look up a peer by its virtual IP.
    pub fn get(&self, ip: &IpAddr) -> Option<Arc<Peer>> {
        self.peers.get(ip).map(|entry| entry.value().clone())
    }

    /// Look up a peer by its `PeerId`, resolving through the secondary index.
    pub fn get_by_peer_id(&self, peer_id: &PeerId) -> Option<Arc<Peer>> {
        let ip = *self.by_peer_id.get(peer_id)?;
        self.get(&ip)
    }

    /// Remove a peer by its virtual IP, clearing its `PeerId` index entry too.
    pub fn remove(&self, ip: &IpAddr) -> Option<Arc<Peer>> {
        let (_, peer) = self.peers.remove(ip)?;
        self.by_peer_id.remove(&peer.info().peer_id);
        Some(peer)
    }

    /// The virtual IPs of all known peers.
    pub fn ips(&self) -> Vec<IpAddr> {
        self.peers.iter().map(|entry| *entry.key()).collect()
    }

    /// All known peers.
    pub fn peers(&self) -> Vec<Arc<Peer>> {
        self.peers
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noeio_common::host_info::new_peer_id;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    const SAMPLE_NET: &str = "550e8400-e29b-41d4-a716-446655440000";
    const LOCAL_ID: PeerId = 7;

    async fn socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn info(peer_id: PeerId, ip: IpAddr, version: u64) -> PeerInfo {
        PeerInfo::new(peer_id, ip, SAMPLE_NET)
            .unwrap()
            .with_resource_version(version)
            .with_nat_addr(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                2026,
            )))
    }

    /// A peer that re-registers under a new id keeps its virtual IP, so the
    /// primary store still resolves — but signalling and delivery both look the
    /// peer up by id, and that index must follow the rename or every inbound
    /// packet is dropped as "unknown peer".
    #[tokio::test]
    async fn update_info_reindexes_new_peer_id() {
        let router = Router::new();
        let ip = IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1));
        let (old_id, new_id) = (new_peer_id(), new_peer_id());

        router.insert(Peer::new(info(old_id, ip, 1), socket().await, LOCAL_ID));
        let existing = router.get(&ip).unwrap();
        router.update_info(&existing, info(new_id, ip, 2), LOCAL_ID);

        let found = router.get_by_peer_id(&new_id).expect("new id must resolve");
        assert_eq!(found.info().noeio_ip, ip);
        assert_eq!(found.info().resource_version, 2);
        assert!(
            router.get_by_peer_id(&old_id).is_none(),
            "stale id must not resolve after a rename"
        );
    }

    /// An update that only bumps the version must leave the index intact — the
    /// remove-then-insert ordering would otherwise erase the peer's own entry.
    #[tokio::test]
    async fn update_info_keeps_index_when_peer_id_is_unchanged() {
        let router = Router::new();
        let ip = IpAddr::V4(Ipv4Addr::new(110, 20, 0, 2));
        let peer_id = new_peer_id();

        router.insert(Peer::new(info(peer_id, ip, 1), socket().await, LOCAL_ID));
        let existing = router.get(&ip).unwrap();
        router.update_info(&existing, info(peer_id, ip, 9), LOCAL_ID);

        let found = router.get_by_peer_id(&peer_id).expect("id must resolve");
        assert_eq!(found.info().resource_version, 9);
        assert_eq!(router.peers().len(), 1);
    }

    /// The same guarantee for the insert path: replacing an IP's occupant under
    /// a new id must not leave the previous id resolving.
    #[tokio::test]
    async fn insert_drops_stale_peer_id_index() {
        let router = Router::new();
        let ip = IpAddr::V4(Ipv4Addr::new(110, 20, 0, 3));
        let (old_id, new_id) = (new_peer_id(), new_peer_id());

        router.insert(Peer::new(info(old_id, ip, 1), socket().await, LOCAL_ID));
        router.insert(Peer::new(info(new_id, ip, 2), socket().await, LOCAL_ID));

        assert!(router.get_by_peer_id(&new_id).is_some());
        assert!(router.get_by_peer_id(&old_id).is_none());
        assert_eq!(router.peers().len(), 1);
    }
}
