//! Native routing-table operations used by noeio.
//!
//! The public API takes the numeric interface index supplied by the TUN crate,
//! so callers stay independent of platform-specific interface-name APIs and no
//! `route`, `ip`, or `netsh` binary is needed at runtime.

use std::{io, net::IpAddr};

#[cfg(target_os = "macos")]
mod macos;

/// Add a route to `target/prefix` through the interface identified by
/// `ifindex`. `metric` is the platform route metric where the native route API
/// supports one.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub async fn add_route(target: IpAddr, prefix: u8, ifindex: u32, metric: u32) -> io::Result<()> {
    check_prefix(target, prefix)?;
    let route = net_route::Route::new(target, prefix)
        .with_ifindex(ifindex)
        .with_metric(metric);

    let handle = net_route::Handle::new()?;
    handle.add(&route).await
}

/// Delete the route to `target/prefix`. When `ifindex` is given only a route
/// through that interface matches, otherwise the first route to the prefix is
/// removed (used by the start-up sweep, when the interface a stale route was
/// bound to may no longer exist).
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub async fn del_route(target: IpAddr, prefix: u8, ifindex: Option<u32>) -> io::Result<()> {
    check_prefix(target, prefix)?;
    let handle = net_route::Handle::new()?;

    // `net_route::Handle::delete` matches on destination/prefix/metric only
    // and ignores the interface, so find the exact entry ourselves and hand
    // back a fully specified route (metric included) for it to remove.
    let existing = handle.list().await?.into_iter().find(|r| {
        r.destination == target
            && r.prefix == prefix
            && ifindex.is_none_or(|want| r.ifindex == Some(want))
    });
    let Some(existing) = existing else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no route to {target}/{prefix} through the given interface"),
        ));
    };
    handle.delete(&existing).await
}

#[cfg(target_os = "macos")]
pub async fn add_route(target: IpAddr, prefix: u8, ifindex: u32, metric: u32) -> io::Result<()> {
    check_prefix(target, prefix)?;
    macos::add_route(target, prefix, ifindex, metric)
}

#[cfg(target_os = "macos")]
pub async fn del_route(target: IpAddr, prefix: u8, ifindex: Option<u32>) -> io::Result<()> {
    check_prefix(target, prefix)?;
    macos::del_route(target, prefix, ifindex)
}

/// Return a useful error when building on a platform unsupported by
/// `net-route`, rather than falling back to a shell command.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn add_route(
    _target: IpAddr,
    _prefix: u8,
    _ifindex: u32,
    _metric: u32,
) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn del_route(_target: IpAddr, _prefix: u8, _ifindex: Option<u32>) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native route management is unsupported on this platform",
    )
}

/// Whether `err` from [`del_route`] means the route was already gone. The
/// reconciler treats that as success: the desired end state holds.
pub fn is_route_missing(err: &io::Error) -> bool {
    match err.raw_os_error() {
        // ESRCH (Linux / macOS "no such process" is what the kernel returns for
        // a missing route), ENOENT, and Windows ERROR_NOT_FOUND.
        Some(3) | Some(2) | Some(1168) => true,
        None => err.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

/// Whether `err` from [`add_route`] means an identical route already exists.
/// Re-adding is how the reconciler heals a route someone deleted by hand, so
/// this outcome is also success.
pub fn is_route_exists(err: &io::Error) -> bool {
    match err.raw_os_error() {
        // EEXIST and Windows ERROR_OBJECT_ALREADY_EXISTS.
        Some(17) | Some(5010) => true,
        None => err.kind() == io::ErrorKind::AlreadyExists,
        _ => false,
    }
}

fn check_prefix(target: IpAddr, prefix: u8) -> io::Result<()> {
    let max = if target.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("prefix length {prefix} is out of range for {target}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rejects_out_of_range_prefix() {
        assert!(check_prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33).is_err());
        assert!(check_prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32).is_ok());
        assert!(check_prefix(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).is_ok());
    }

    #[test]
    fn classifies_missing_and_existing_route_errors() {
        assert!(is_route_missing(&io::Error::from_raw_os_error(3)));
        assert!(is_route_missing(&io::Error::from_raw_os_error(2)));
        assert!(is_route_missing(&io::Error::new(
            io::ErrorKind::NotFound,
            "x"
        )));
        assert!(!is_route_missing(&io::Error::from_raw_os_error(13)));

        assert!(is_route_exists(&io::Error::from_raw_os_error(17)));
        assert!(!is_route_exists(&io::Error::from_raw_os_error(13)));
    }

    /// Adding then deleting a real route needs privileges and a live
    /// interface, so this only runs when explicitly requested:
    /// `NOEIO_ROUTE_IFINDEX=<ifindex> cargo test -p noeio-net-route -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn add_then_delete_roundtrip() {
        let ifindex: u32 = std::env::var("NOEIO_ROUTE_IFINDEX")
            .expect("set NOEIO_ROUTE_IFINDEX to an interface index")
            .parse()
            .unwrap();
        let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0));
        add_route(target, 24, ifindex, 7).await.expect("add_route");
        del_route(target, 24, Some(ifindex))
            .await
            .expect("del_route");
        // A second delete must report the route as missing, not some other
        // failure — that is what the reconciler relies on.
        let err = del_route(target, 24, Some(ifindex)).await.unwrap_err();
        assert!(is_route_missing(&err), "unexpected error: {err}");
    }
}
