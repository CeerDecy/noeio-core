use crate::daemon::peer::Peer;
use dashmap::DashMap;
use noeio_common::host_info::PeerId;
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
