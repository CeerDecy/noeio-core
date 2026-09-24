use crate::daemon::peer::Peer;
use dashmap::DashMap;
use noeio_common::host_info::{PeerId, PeerInfo};
use smoltcp::wire::Ipv4Cidr;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Concurrent routing table of known peers.
///
/// Peers are stored once, keyed by their virtual IP ([`IpAddr`]). A secondary
/// index maps each peer's [`PeerId`] to that virtual IP, so a peer can be looked
/// up by either key without duplicating the [`Peer`] itself.
///
/// A third table, `subnets`, holds the accepted subnet routes: which peer is
/// the exit for which prefix. [`Router::lookup`] consults it only after the
/// exact table misses, so pure host-to-host traffic never pays for it.
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
    /// Accepted subnet routes, sorted by prefix length descending so a linear
    /// scan is a longest-prefix match. A `Vec` under `RwLock` rather than a
    /// trie on purpose: the expected size is tens of entries, the write rate
    /// is "when a peer's advertisement changes", and the read path takes
    /// only an uncontended read lock. Replace with an LPM trie if the table
    /// grows past a few hundred entries.
    subnets: RwLock<Vec<(Ipv4Cidr, PeerId)>>,
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

    /// The peer that should carry a packet to `ip`: an exact host route if
    /// one exists (a peer's own overlay address always wins), otherwise the
    /// longest accepted subnet prefix containing `ip`.
    ///
    /// This is the outbound hot path. The exact lookup is the same
    /// `DashMap::get` as before; the prefix scan only runs on a miss.
    pub fn lookup(&self, ip: &IpAddr) -> Option<Arc<Peer>> {
        if let Some(peer) = self.get(ip) {
            return Some(peer);
        }
        let IpAddr::V4(v4) = ip else {
            return None;
        };
        let peer_id = {
            let subnets = self.subnets.read().unwrap();
            subnets
                .iter()
                .find(|(cidr, _)| cidr.contains_addr(v4))
                .map(|(_, peer_id)| *peer_id)?
        };
        self.get_by_peer_id(&peer_id)
    }

    /// Replace the accepted subnet table wholesale. Callers compute the full
    /// desired set (every accepted `(cidr, exit peer)`) and hand it over; a
    /// withdrawn route is simply absent from the new list.
    pub fn set_subnets(&self, mut entries: Vec<(Ipv4Cidr, PeerId)>) {
        entries.sort_by(|a, b| {
            b.0.prefix_len()
                .cmp(&a.0.prefix_len())
                .then_with(|| a.0.cmp(&b.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        entries.dedup();
        *self.subnets.write().unwrap() = entries;
    }

    /// Snapshot of the accepted subnet table.
    pub fn subnets(&self) -> Vec<(Ipv4Cidr, PeerId)> {
        self.subnets.read().unwrap().clone()
    }

    /// Whether `peer` is allowed to source a decrypted packet from `src`: the
    /// WireGuard `AllowedIPs` rule. Its own overlay address always is; so is
    /// anything inside a subnet it advertises. Nothing else — this is the
    /// anti-spoofing boundary, so the check is against what the peer
    /// *advertises*, not what we accepted (a standby exit still forwards
    /// legitimately for flows that were routed to it earlier).
    pub fn allowed_source(info: &PeerInfo, src: IpAddr) -> bool {
        if src == info.noeio_ip {
            return true;
        }
        let IpAddr::V4(v4) = src else {
            return false;
        };
        info.advertised_routes.iter().any(|c| c.contains_addr(&v4))
    }

    /// Remove a peer by its virtual IP, clearing its `PeerId` index entry and
    /// any subnet routes it was the exit for.
    pub fn remove(&self, ip: &IpAddr) -> Option<Arc<Peer>> {
        let (_, peer) = self.peers.remove(ip)?;
        let peer_id = peer.info().peer_id;
        self.by_peer_id.remove(&peer_id);
        self.subnets
            .write()
            .unwrap()
            .retain(|(_, exit)| *exit != peer_id);
        Some(peer)
    }

    /// Remove a peer by id. See [`Self::remove`].
    pub fn remove_by_peer_id(&self, peer_id: &PeerId) -> Option<Arc<Peer>> {
        let ip = *self.by_peer_id.get(peer_id)?;
        self.remove(&ip)
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
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

    /// AC-7: two exits, nested prefixes.
    async fn subnet_router() -> (Router, PeerId, PeerId) {
        let router = Router::new();
        let (a, d) = (new_peer_id(), new_peer_id());
        router.insert(Peer::new(
            info(a, ip("110.20.0.1"), 1),
            socket().await,
            LOCAL_ID,
        ));
        router.insert(Peer::new(
            info(d, ip("110.20.0.9"), 1),
            socket().await,
            LOCAL_ID,
        ));
        router.set_subnets(vec![
            (cidr("10.0.0.0/8"), d),
            (cidr("192.168.10.0/24"), a),
            (cidr("10.1.0.0/16"), a),
        ]);
        (router, a, d)
    }

    #[tokio::test]
    async fn lookup_prefers_exact_host_route() {
        let (router, a, _d) = subnet_router().await;
        // A's overlay IP also sits inside a subnet D advertises; the host
        // route must still win.
        router.set_subnets(vec![(cidr("110.20.0.0/16"), _d)]);
        assert_eq!(router.lookup(&ip("110.20.0.1")).unwrap().info().peer_id, a);
    }

    #[tokio::test]
    async fn lookup_longest_prefix_match() {
        let (router, a, d) = subnet_router().await;
        assert_eq!(router.lookup(&ip("10.1.2.3")).unwrap().info().peer_id, a);
        assert_eq!(router.lookup(&ip("10.2.2.3")).unwrap().info().peer_id, d);
        assert_eq!(
            router.lookup(&ip("192.168.10.7")).unwrap().info().peer_id,
            a
        );
    }

    #[tokio::test]
    async fn lookup_miss_returns_none() {
        let (router, _, _) = subnet_router().await;
        assert!(router.lookup(&ip("172.16.0.1")).is_none());
        assert!(router.lookup(&ip("fd00::1")).is_none());
    }

    #[tokio::test]
    async fn set_subnets_replaces_and_orders() {
        let (router, a, d) = subnet_router().await;
        router.set_subnets(vec![(cidr("10.0.0.0/8"), a)]);
        assert_eq!(router.subnets(), vec![(cidr("10.0.0.0/8"), a)]);
        assert_eq!(router.lookup(&ip("10.1.2.3")).unwrap().info().peer_id, a);
        assert!(router.lookup(&ip("192.168.10.7")).is_none());
        let _ = d;
    }

    #[tokio::test]
    async fn remove_drops_the_peers_subnets() {
        let (router, a, d) = subnet_router().await;
        router.remove_by_peer_id(&a);
        assert!(router.get_by_peer_id(&a).is_none());
        assert!(router.lookup(&ip("192.168.10.7")).is_none());
        // D's routes are untouched, and the nested /16 that A owned now
        // falls through to D's /8.
        assert_eq!(router.lookup(&ip("10.1.2.3")).unwrap().info().peer_id, d);
    }

    /// AC-7: concurrent readers on the hot path while the table is swapped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lookup_is_safe_under_concurrent_set_subnets() {
        let (router, a, d) = subnet_router().await;
        let router = Arc::new(router);
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let r = router.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..2000 {
                    let found = r.lookup(&ip("10.1.2.3")).map(|p| p.info().peer_id);
                    assert!(found.is_none() || found == Some(a) || found == Some(d));
                }
            }));
        }
        for i in 0..2000 {
            if i % 2 == 0 {
                router.set_subnets(vec![(cidr("10.0.0.0/8"), d)]);
            } else {
                router.set_subnets(vec![(cidr("10.0.0.0/8"), d), (cidr("10.1.0.0/16"), a)]);
            }
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    /// AC-9: AllowedIPs semantics.
    #[test]
    fn allowed_source_is_own_ip_or_advertised_subnet() {
        let peer =
            info(1, ip("110.20.0.1"), 1).with_advertised_routes(vec![cidr("192.168.10.0/24")]);
        assert!(Router::allowed_source(&peer, ip("110.20.0.1")));
        assert!(Router::allowed_source(&peer, ip("192.168.10.7")));
        assert!(!Router::allowed_source(&peer, ip("192.168.11.7")));
        assert!(!Router::allowed_source(&peer, ip("110.20.0.2")));
        assert!(!Router::allowed_source(&peer, ip("fd00::1")));

        let plain = info(2, ip("110.20.0.2"), 1);
        assert!(Router::allowed_source(&plain, ip("110.20.0.2")));
        assert!(!Router::allowed_source(&plain, ip("192.168.10.7")));
    }
}
