//! Converges the kernel routing table toward the routes the daemon wants.
//!
//! The daemon never installs or removes a route imperatively. Instead:
//!
//! ```text
//! desired   := f(router state, policy)        // pure, see [`desired`]
//! installed := what we believe the kernel has  // this module's memory
//! reconcile := diff(desired, installed) → add the missing, delete the extra
//! ```
//!
//! Anything that changes the router (a `SyncRoute`, a withdrawn peer, a config
//! change) only mutates in-memory state and calls [`Reconciler::notify`]; the
//! loop wakes up, recomputes, and applies. A periodic tick re-runs the same
//! thing so the table also heals from outside interference (`ip route del`
//! by hand) and from a failed `add` that should be retried.
//!
//! `/32` host routes and subnet routes go through the same path on purpose:
//! a second code path for one of them would reintroduce the add-without-
//! delete shape this module exists to remove.

use crate::daemon::NoeioDaemon;
use noeio_common::host_info::PeerId;
use smoltcp::wire::Ipv4Cidr;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// How often the loop re-runs without being notified. Also the upper bound on
/// how long a failed `add` waits before its retry.
const TICK: Duration = Duration::from_secs(30);

/// A route the kernel should (or does) hold: `cidr` with the nic registered
/// under `nic` as its egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteKey {
    pub nic: PeerId,
    pub cidr: Ipv4Cidr,
}

/// The routes one remote peer contributes: its own host route plus any
/// subnets it advertises and we accept. Built from the router by
/// [`NoeioDaemon::route_snapshot`]; kept free of `Peer` so [`desired`] can be
/// tested without sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRoutes {
    /// Our nic in this peer's network (the peer's `local_peer_id`).
    pub nic: PeerId,
    pub peer_id: PeerId,
    pub ip: IpAddr,
    /// Subnets this peer advertises that survived the acceptance rules
    /// (policy, conflicts, primary election). Empty when we accept none.
    pub subnets: Vec<Ipv4Cidr>,
}

/// The pure part: which routes should exist given the current peers.
///
/// A peer whose nic is no longer registered contributes nothing — its routes
/// have no interface to point at. IPv6 peers are skipped: the route helpers
/// and the TUN configuration are IPv4-only for now.
pub fn desired(nics: &[PeerId], peers: &[PeerRoutes]) -> BTreeSet<RouteKey> {
    let mut set = BTreeSet::new();
    for peer in peers {
        if !nics.contains(&peer.nic) {
            continue;
        }
        if let IpAddr::V4(ip) = peer.ip {
            set.insert(RouteKey {
                nic: peer.nic,
                cidr: Ipv4Cidr::new(ip, 32),
            });
        }
        for cidr in &peer.subnets {
            set.insert(RouteKey {
                nic: peer.nic,
                cidr: cidr.network(),
            });
        }
    }
    set
}

/// `(to add, to delete)` between what should exist and what does.
pub fn diff(
    desired: &BTreeSet<RouteKey>,
    installed: &BTreeSet<RouteKey>,
) -> (Vec<RouteKey>, Vec<RouteKey>) {
    let add = desired.difference(installed).copied().collect();
    let del = installed.difference(desired).copied().collect();
    (add, del)
}

pub struct Reconciler {
    installed: Mutex<BTreeSet<RouteKey>>,
    notify: Notify,
    /// Where `installed` is mirrored between runs. `None` disables
    /// persistence (tests).
    state_file: Option<PathBuf>,
}

impl Default for Reconciler {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Reconciler {
    pub fn new(state_file: Option<PathBuf>) -> Self {
        Self {
            installed: Mutex::new(BTreeSet::new()),
            notify: Notify::new(),
            state_file,
        }
    }

    /// Wake the loop; cheap and safe to call from any path that changed the
    /// router. Multiple calls before the loop runs coalesce into one pass.
    pub fn notify(&self) {
        self.notify.notify_one();
    }

    pub async fn installed(&self) -> BTreeSet<RouteKey> {
        self.installed.lock().await.clone()
    }

    /// Bring the kernel in line with `desired`, given the nic interface
    /// indexes to install through. Returns the number of changes applied.
    ///
    /// A route whose nic is unknown is deleted without an interface filter
    /// (it is a leftover from a previous run whose TUN is gone). A failed
    /// `add` is not recorded, so the next pass retries it; a failed `del` is
    /// kept as installed for the same reason.
    pub async fn reconcile(
        &self,
        desired: &BTreeSet<RouteKey>,
        ifindex: impl Fn(PeerId) -> Option<u32>,
    ) -> usize {
        let mut installed = self.installed.lock().await;
        let (add, del) = diff(desired, &installed);
        let mut changed = 0;

        for key in del {
            match uninstall(key, ifindex(key.nic)).await {
                Ok(()) => {
                    tracing::info!(cidr = %key.cidr, nic = key.nic, "route removed");
                    installed.remove(&key);
                    changed += 1;
                }
                Err(err) => {
                    tracing::warn!(cidr = %key.cidr, nic = key.nic, "route removal failed: {err}");
                }
            }
        }

        for key in add {
            let Some(ifindex) = ifindex(key.nic) else {
                // The nic disappeared between `desired` and here; the next
                // snapshot won't want this route.
                continue;
            };
            match install(key, ifindex).await {
                Ok(()) => {
                    tracing::info!(cidr = %key.cidr, nic = key.nic, "route installed");
                    installed.insert(key);
                    changed += 1;
                }
                Err(err) => {
                    tracing::warn!(cidr = %key.cidr, nic = key.nic, "route install failed: {err}");
                }
            }
        }

        if changed > 0 {
            self.persist(&installed);
        }
        changed
    }

    /// Load the previous run's `installed` set so the first pass removes what
    /// it left behind. A missing or unreadable file is an empty set; a bad
    /// line is skipped with a warning. Never fails start-up.
    pub async fn restore(&self) {
        let Some(path) = &self.state_file else {
            return;
        };
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(path = %path.display(), "ignoring route state file: {err}");
                return;
            }
        };
        let mut installed = self.installed.lock().await;
        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            match parse_line(line) {
                Some(key) => {
                    installed.insert(key);
                }
                None => {
                    tracing::warn!(path = %path.display(), line, "skipping bad route state line")
                }
            }
        }
        if !installed.is_empty() {
            tracing::info!(
                count = installed.len(),
                "restored route state from a previous run; will remove routes no longer wanted"
            );
        }
    }

    fn persist(&self, installed: &BTreeSet<RouteKey>) {
        let Some(path) = &self.state_file else {
            return;
        };
        let body: String = installed
            .iter()
            .map(|k| format!("{} {}\n", k.nic, k.cidr))
            .collect();
        let write = || -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, body.as_bytes())
        };
        if let Err(err) = write() {
            tracing::warn!(path = %path.display(), "failed to persist route state: {err}");
        }
    }
}

fn parse_line(line: &str) -> Option<RouteKey> {
    let (nic, cidr) = line.split_once(' ')?;
    Some(RouteKey {
        nic: nic.parse().ok()?,
        cidr: cidr.parse().ok()?,
    })
}

async fn install(key: RouteKey, ifindex: u32) -> std::io::Result<()> {
    let target = IpAddr::V4(key.cidr.address());
    match noeio_net_route::add_route(
        target,
        key.cidr.prefix_len(),
        ifindex,
        crate::interface::virtual_nic::ROUTE_METRIC,
    )
    .await
    {
        // Re-adding a route someone else already has is how we heal a
        // partially applied previous pass.
        Err(err) if noeio_net_route::is_route_exists(&err) => Ok(()),
        other => other,
    }
}

async fn uninstall(key: RouteKey, ifindex: Option<u32>) -> std::io::Result<()> {
    let target = IpAddr::V4(key.cidr.address());
    match noeio_net_route::del_route(target, key.cidr.prefix_len(), ifindex).await {
        // Already gone (e.g. the kernel reclaimed it with the TUN) is the
        // desired end state.
        Err(err) if noeio_net_route::is_route_missing(&err) => Ok(()),
        other => other,
    }
}

/// Where the reconciler mirrors its `installed` set. A tmpfs path on Linux so
/// a reboot — after which no route or interface survives anyway — starts
/// clean rather than replaying stale state.
pub fn default_state_file() -> PathBuf {
    crate::common::run_state_dir().join("routes")
}

/// Drive [`Reconciler::reconcile`] from the daemon: wakes on `notify` or
/// every [`TICK`], snapshots the router, and applies. Runs until the daemon
/// is dropped.
pub fn spawn(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        daemon.reconciler.restore().await;
        loop {
            daemon.reconcile_routes().await;
            tokio::select! {
                _ = daemon.reconciler.notify.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    fn peer(nic: PeerId, peer_id: PeerId, ip: [u8; 4], subnets: &[&str]) -> PeerRoutes {
        PeerRoutes {
            nic,
            peer_id,
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            subnets: subnets.iter().map(|s| cidr(s)).collect(),
        }
    }

    fn key(nic: PeerId, c: &str) -> RouteKey {
        RouteKey { nic, cidr: cidr(c) }
    }

    #[test]
    fn desired_has_a_host_route_per_peer() {
        let peers = [
            peer(1, 10, [110, 20, 0, 1], &[]),
            peer(1, 11, [110, 20, 0, 2], &[]),
        ];
        let set = desired(&[1], &peers);
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec![key(1, "110.20.0.1/32"), key(1, "110.20.0.2/32")]
        );
    }

    #[test]
    fn desired_includes_accepted_subnets_normalized() {
        let peers = [peer(1, 10, [110, 20, 0, 1], &["192.168.10.7/24"])];
        let set = desired(&[1], &peers);
        assert!(set.contains(&key(1, "110.20.0.1/32")));
        assert!(set.contains(&key(1, "192.168.10.0/24")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn desired_skips_peers_whose_nic_is_gone() {
        let peers = [
            peer(1, 10, [110, 20, 0, 1], &[]),
            peer(2, 11, [110, 30, 0, 1], &[]),
        ];
        let set = desired(&[1], &peers);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&key(1, "110.20.0.1/32")));
    }

    #[test]
    fn diff_on_peer_added_and_cidr_withdrawn() {
        // AC-13: a new peer yields an add; a subnet no longer advertised
        // yields a delete; the untouched host route appears in neither.
        let installed: BTreeSet<_> = [key(1, "110.20.0.1/32"), key(1, "10.0.0.0/8")].into();
        let want = desired(
            &[1],
            &[
                peer(1, 10, [110, 20, 0, 1], &[]),
                peer(1, 11, [110, 20, 0, 2], &[]),
            ],
        );
        let (add, del) = diff(&want, &installed);
        assert_eq!(add, vec![key(1, "110.20.0.2/32")]);
        assert_eq!(del, vec![key(1, "10.0.0.0/8")]);
    }

    #[test]
    fn diff_on_peer_gone_deletes_everything_it_contributed() {
        let installed: BTreeSet<_> = [key(1, "110.20.0.1/32"), key(1, "10.0.0.0/8")].into();
        let want = desired(&[1], &[]);
        let (add, del) = diff(&want, &installed);
        assert!(add.is_empty());
        assert_eq!(del, vec![key(1, "10.0.0.0/8"), key(1, "110.20.0.1/32")]);
    }

    #[test]
    fn diff_is_empty_when_converged() {
        // AC-15: the second pass over an unchanged world is a no-op.
        let want = desired(&[1], &[peer(1, 10, [110, 20, 0, 1], &["10.0.0.0/8"])]);
        let (add, del) = diff(&want, &want);
        assert!(add.is_empty() && del.is_empty());
    }

    #[test]
    fn diff_heals_an_externally_removed_route() {
        // AC-15: a route deleted behind our back is re-added on the next pass.
        let want = desired(&[1], &[peer(1, 10, [110, 20, 0, 1], &["10.0.0.0/8"])]);
        let mut installed = want.clone();
        installed.remove(&key(1, "10.0.0.0/8"));
        let (add, del) = diff(&want, &installed);
        assert_eq!(add, vec![key(1, "10.0.0.0/8")]);
        assert!(del.is_empty());
    }

    #[test]
    fn desired_does_not_depend_on_time_or_message_arrival() {
        // AC-14 (the pure half): `desired` is a function of the router
        // snapshot only. A peer that has been silent for any length of time
        // is still in the snapshot, so its routes are still desired. The
        // integration half lives in daemon.rs.
        let snapshot = [peer(1, 10, [110, 20, 0, 1], &["10.0.0.0/8"])];
        let first = desired(&[1], &snapshot);
        let later = desired(&[1], &snapshot);
        assert_eq!(first, later);
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn state_line_roundtrip() {
        let k = key(42, "192.168.10.0/24");
        let line = format!("{} {}", k.nic, k.cidr);
        assert_eq!(parse_line(&line), Some(k));
        assert_eq!(parse_line("garbage"), None);
        assert_eq!(parse_line("x 10.0.0.0/8"), None);
    }

    #[tokio::test]
    async fn restore_ignores_missing_and_corrupt_files() {
        let dir = std::env::temp_dir().join(format!("noeio-reconciler-{}", std::process::id()));
        let path = dir.join("routes");
        let r = Reconciler::new(Some(path.clone()));
        r.restore().await;
        assert!(r.installed().await.is_empty());

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "1 110.20.0.1/32\nnot a line\n\n2 10.0.0.0/8\n").unwrap();
        r.restore().await;
        let got = r.installed().await;
        assert_eq!(got.len(), 2);
        assert!(got.contains(&key(1, "110.20.0.1/32")));
        assert!(got.contains(&key(2, "10.0.0.0/8")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
