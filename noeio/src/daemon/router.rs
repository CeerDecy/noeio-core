use crate::daemon::peer::Peer;
use dashmap::DashMap;
use dashmap::mapref::one::{Ref, RefMut};
use noeio_common::host_info::PeerId;
use std::net::IpAddr;

/// Concurrent routing table of known peers.
///
/// Peers are stored once, keyed by their virtual IP ([`IpAddr`]). A secondary
/// index maps each peer's [`PeerId`] to that virtual IP, so a peer can be looked
/// up by either key without duplicating the [`Peer`] itself.
#[derive(Default)]
pub struct Router {
    /// Primary store: virtual IP -> peer.
    peers: DashMap<IpAddr, Peer>,
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
    pub fn insert(&self, peer: Peer) {
        let ip = peer.info.noeio_ip;
        let peer_id = peer.info.peer_id;
        if let Some(old) = self.peers.insert(ip, peer) {
            if old.info.peer_id != peer_id {
                self.by_peer_id.remove(&old.info.peer_id);
            }
        }
        self.by_peer_id.insert(peer_id, ip);
    }

    /// Look up a peer by its virtual IP.
    pub fn get(&self, ip: &IpAddr) -> Option<Ref<'_, IpAddr, Peer>> {
        self.peers.get(ip)
    }

    /// Look up a peer by its virtual IP for mutation.
    pub fn get_mut(&self, ip: &IpAddr) -> Option<RefMut<'_, IpAddr, Peer>> {
        self.peers.get_mut(ip)
    }

    /// Look up a peer by its `PeerId`, resolving through the secondary index.
    pub fn get_by_peer_id(&self, peer_id: &PeerId) -> Option<Ref<'_, IpAddr, Peer>> {
        let ip = *self.by_peer_id.get(peer_id)?;
        self.peers.get(&ip)
    }

    /// Look up a peer by its `PeerId` for mutation.
    pub fn get_mut_by_peer_id(&self, peer_id: &PeerId) -> Option<RefMut<'_, IpAddr, Peer>> {
        let ip = *self.by_peer_id.get(peer_id)?;
        self.peers.get_mut(&ip)
    }

    /// Remove a peer by its virtual IP, clearing its `PeerId` index entry too.
    pub fn remove(&self, ip: &IpAddr) -> Option<Peer> {
        let (_, peer) = self.peers.remove(ip)?;
        self.by_peer_id.remove(&peer.info.peer_id);
        Some(peer)
    }

    /// The virtual IPs of all known peers.
    pub fn ips(&self) -> Vec<IpAddr> {
        self.peers.iter().map(|entry| *entry.key()).collect()
    }
}
