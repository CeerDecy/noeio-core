//! Advertiser-side forwarding and SNAT (Linux only).
//!
//! A node that advertises subnets must forward packets from the overlay into
//! its LAN and masquerade them so replies come back to it. Both pieces of
//! state outlive the process — `ip_forward` is a sysctl, the nftables table
//! lives in the kernel — so unlike routes they need explicit cleanup at
//! start-up (a previous run may have died) and at shutdown.
//!
//! Convergence here is "rebuild the whole table", not a diff: the ruleset is
//! four to six rules and an atomic replace is simpler and safer than tracking
//! handles. See `noeio_net_route::nftables` for the encoding.

use crate::daemon::NoeioDaemon;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// What the NAT layer currently has applied, so `converge` can skip a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NatState {
    pub applied: Option<AppliedNat>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedNat {
    pub overlay: (Ipv4Addr, u8),
    pub lan_if: String,
    pub tun_if: String,
}

/// Remove anything a previous run may have left behind: the `noeio` table
/// and a modified `ip_forward`. Idempotent; called before the first
/// converge. A failure here is logged, not fatal — a consumer-only node has
/// no need for netfilter and must still start (FR-8.8 / FR-8.9).
#[cfg(target_os = "linux")]
pub async fn sweep_leftovers() {
    let run_dir = crate::common::run_state_dir();
    let result = tokio::task::spawn_blocking(move || -> Result<(bool, bool), String> {
        let restored = noeio_net_route::forwarding::restore(&run_dir).map_err(|e| e.to_string())?;
        let mut nf = noeio_net_route::nftables::NfSocket::open().map_err(|e| e.to_string())?;
        let had_table = nf.table_exists().map_err(|e| e.to_string())?;
        if had_table {
            nf.clear().map_err(|e| e.to_string())?;
        }
        Ok((restored, had_table))
    })
    .await;
    match result {
        Ok(Ok((restored, had_table))) => {
            if restored || had_table {
                tracing::warn!(
                    ip_forward_restored = restored,
                    nft_table_removed = had_table,
                    "cleaned up netfilter state left by a previous run"
                );
            }
        }
        Ok(Err(err)) => tracing::debug!("netfilter start-up sweep skipped: {err}"),
        Err(err) => tracing::warn!("netfilter start-up sweep panicked: {err}"),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn sweep_leftovers() {}

/// Bring the kernel's forwarding + NAT state in line with what this node
/// advertises. Nothing advertised (or `auto_nat = false`) means the table is
/// removed and `ip_forward` restored.
#[cfg(target_os = "linux")]
pub async fn converge(daemon: &Arc<NoeioDaemon>) {
    use noeio_net_route::{forwarding, nftables};

    let advertised = daemon.advertised_routes();
    let want = if advertised.is_empty() || !daemon.config.router.auto_nat {
        None
    } else {
        match nat_target(daemon) {
            Ok(t) => Some(t),
            Err(err) => {
                tracing::error!("cannot set up subnet-router NAT: {err}");
                None
            }
        }
    };

    let current = daemon.nat_state.lock().unwrap().applied.clone();
    if current == want {
        return;
    }

    let run_dir = crate::common::run_state_dir();
    let want_clone = want.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut nf = nftables::NfSocket::open().map_err(|e| e.to_string())?;
        match &want_clone {
            Some(t) => {
                let rules = nftables::Ruleset::new(t.overlay, &t.lan_if, &t.tun_if, true)
                    .map_err(|e| e.to_string())?;
                // Order: rules first, then forwarding. If the rules fail we
                // never opened the host up.
                nf.apply(&rules).map_err(|e| e.to_string())?;
                if forwarding::enable(&run_dir).map_err(|e| e.to_string())? {
                    tracing::warn!(
                        "enabled net.ipv4.ip_forward: this host now forwards IPv4 between all its interfaces, not only noeio traffic"
                    );
                }
                Ok(())
            }
            None => {
                nf.clear().map_err(|e| e.to_string())?;
                forwarding::restore(&run_dir).map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            match &want {
                Some(t) => tracing::info!(
                    overlay = %format!("{}/{}", t.overlay.0, t.overlay.1),
                    lan_if = %t.lan_if,
                    tun_if = %t.tun_if,
                    "subnet-router NAT applied"
                ),
                None => tracing::info!("subnet-router NAT removed"),
            }
            daemon.nat_state.lock().unwrap().applied = want;
        }
        Ok(Err(err)) => tracing::error!("subnet-router NAT: {err}"),
        Err(err) => tracing::error!("subnet-router NAT task panicked: {err}"),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn converge(_daemon: &Arc<NoeioDaemon>) {}

/// Resolve the inputs for the ruleset: the overlay range to masquerade, the
/// LAN egress interface, and our TUN name.
#[cfg(target_os = "linux")]
fn nat_target(daemon: &Arc<NoeioDaemon>) -> Result<AppliedNat, String> {
    let nics = daemon.nics.interfaces();
    let (_, tun_if) = nics
        .first()
        .cloned()
        .ok_or_else(|| "no virtual nic registered yet".to_string())?;

    // The overlay range: the smallest prefix that contains every overlay IP
    // we know (ours and our peers'). Peers are the only sources that will
    // ever arrive through the TUN, so masquerading exactly them is the
    // narrowest correct rule. Falls back to our own /32 with no peers.
    let mut ips: Vec<Ipv4Addr> = daemon
        .nics
        .ips()
        .into_iter()
        .chain(daemon.router.ips())
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    ips.sort();
    ips.dedup();
    let overlay = covering_prefix(&ips).ok_or_else(|| "no IPv4 overlay address".to_string())?;

    let lan_if = if daemon.config.router.lan_interface.is_empty() {
        default_lan_interface(&daemon.advertised_routes(), &tun_if)?
    } else {
        daemon.config.router.lan_interface.clone()
    };

    Ok(AppliedNat {
        overlay,
        lan_if,
        tun_if,
    })
}

/// Smallest CIDR containing every address in `ips` (sorted, non-empty).
pub fn covering_prefix(ips: &[Ipv4Addr]) -> Option<(Ipv4Addr, u8)> {
    let first = u32::from(*ips.first()?);
    let last = u32::from(*ips.last()?);
    let differing = (first ^ last).leading_zeros() as u8;
    let prefix = differing.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((Ipv4Addr::from(first & mask), prefix))
}

/// Pick the physical interface that sits on the first advertised subnet: the
/// one whose address is inside it. Not the TUN, not loopback.
#[cfg(target_os = "linux")]
fn default_lan_interface(
    advertised: &[smoltcp::wire::Ipv4Cidr],
    tun_if: &str,
) -> Result<String, String> {
    let ifaces = pnet::datalink::interfaces();
    for cidr in advertised {
        for iface in &ifaces {
            if iface.name == tun_if || iface.is_loopback() {
                continue;
            }
            for net in &iface.ips {
                if let pnet::ipnetwork::IpNetwork::V4(v4) = net
                    && cidr.contains_addr(&v4.ip())
                {
                    return Ok(iface.name.clone());
                }
            }
        }
    }
    Err(format!(
        "no physical interface has an address inside any advertised subnet ({}); set [router] lan_interface explicitly",
        advertised
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn covering_prefix_of_one_is_host() {
        assert_eq!(
            covering_prefix(&[ip("110.20.0.5")]),
            Some((ip("110.20.0.5"), 32))
        );
    }

    #[test]
    fn covering_prefix_spans_sorted_range() {
        let ips = [ip("110.20.0.1"), ip("110.20.0.5"), ip("110.20.0.9")];
        assert_eq!(covering_prefix(&ips), Some((ip("110.20.0.0"), 28)));
        let ips = [ip("110.20.0.1"), ip("110.20.3.200")];
        assert_eq!(covering_prefix(&ips), Some((ip("110.20.0.0"), 22)));
        assert_eq!(covering_prefix(&[]), None);
    }
}
