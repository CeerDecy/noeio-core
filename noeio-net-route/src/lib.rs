//! Native routing-table operations used by noeio.
//!
//! The public API takes the numeric interface index supplied by the TUN crate,
//! so callers stay independent of platform-specific interface-name APIs and no
//! `route`, `ip`, or `netsh` binary is needed at runtime.

use std::{io, net::IpAddr};

#[cfg(target_os = "macos")]
mod macos;

/// Add a route to `target` through the interface identified by `ifindex`.
///
/// `netmask` must be a contiguous IPv4 netmask (for example,
/// `255.255.255.255`) and `metric` is the platform route metric where the
/// native route API supports one.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub async fn add_route(target: IpAddr, netmask: &str, ifindex: u32, metric: u32) -> io::Result<()> {
    let prefix = netmask_to_prefix(netmask)?;
    let route = net_route::Route::new(target, prefix)
        .with_ifindex(ifindex)
        .with_metric_if_supported(metric);

    let handle = net_route::Handle::new()?;
    handle.add(&route).await
}

#[cfg(target_os = "macos")]
pub async fn add_route(target: IpAddr, netmask: &str, ifindex: u32, metric: u32) -> io::Result<()> {
    let prefix = netmask_to_prefix(netmask)?;
    macos::add_route(target, prefix, ifindex, metric)
}

/// Return a useful error when building on a platform unsupported by
/// `net-route`, rather than falling back to a shell command.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn add_route(
    _target: IpAddr,
    _netmask: &str,
    _ifindex: u32,
    _metric: u32,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native route management is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn netmask_to_prefix(netmask: &str) -> io::Result<u8> {
    let addr: std::net::Ipv4Addr = netmask.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid netmask: {netmask}"),
        )
    })?;
    let bits = u32::from(addr);
    let prefix = bits.leading_ones();
    let expected = match prefix {
        0 => 0,
        32 => u32::MAX,
        _ => !0u32 << (32 - prefix),
    };
    if bits != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-contiguous netmask: {netmask}"),
        ));
    }
    Ok(prefix as u8)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
trait WithMetricIfSupported {
    fn with_metric_if_supported(self, metric: u32) -> Self;
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl WithMetricIfSupported for net_route::Route {
    fn with_metric_if_supported(self, metric: u32) -> Self {
        self.with_metric(metric)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    use super::netmask_to_prefix;

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn parses_contiguous_netmasks() {
        assert_eq!(netmask_to_prefix("255.255.255.255").unwrap(), 32);
        assert_eq!(netmask_to_prefix("255.255.255.0").unwrap(), 24);
        assert_eq!(netmask_to_prefix("0.0.0.0").unwrap(), 0);
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn rejects_non_contiguous_netmasks() {
        assert!(netmask_to_prefix("255.0.255.0").is_err());
    }
}
