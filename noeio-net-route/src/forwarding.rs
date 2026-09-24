//! `net.ipv4.ip_forward` with a saved original (Linux).
//!
//! Unlike routes through the TUN, a sysctl outlives the process. The value it
//! had before noeio touched it is written to a file under the run-state
//! directory; on the next start that file, if present, means the previous
//! run did not get to restore it, and we do so before anything else.

use std::io;
use std::path::{Path, PathBuf};

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

pub fn read() -> io::Result<bool> {
    Ok(std::fs::read_to_string(IP_FORWARD)?.trim() == "1")
}

fn write(enabled: bool) -> io::Result<()> {
    std::fs::write(IP_FORWARD, if enabled { b"1\n" } else { b"0\n" }).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                e.kind(),
                format!("cannot write {IP_FORWARD}: {e}. noeio needs CAP_NET_ADMIN (and a writable /proc/sys) to act as a subnet router"),
            )
        } else {
            e
        }
    })
}

/// Where the pre-noeio value is kept while forwarding is enabled.
pub fn saved_path(run_dir: &Path) -> PathBuf {
    run_dir.join("ip_forward.orig")
}

/// Enable forwarding, remembering the current value first. Returns whether
/// this call changed anything. Idempotent: an existing saved value is kept
/// (it is the true original), not overwritten with our own `1`.
pub fn enable(run_dir: &Path) -> io::Result<bool> {
    let path = saved_path(run_dir);
    let current = read()?;
    if !path.exists() {
        std::fs::create_dir_all(run_dir)?;
        std::fs::write(&path, if current { "1" } else { "0" })?;
    }
    if current {
        return Ok(false);
    }
    write(true)?;
    Ok(true)
}

/// Put forwarding back to the saved original and forget it. A missing saved
/// value means we never changed it (or already restored), so nothing to do.
pub fn restore(run_dir: &Path) -> io::Result<bool> {
    let path = saved_path(run_dir);
    let saved = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let original = saved.trim() == "1";
    if read()? != original {
        write(original)?;
    }
    std::fs::remove_file(&path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_path_lives_under_run_dir() {
        assert_eq!(
            saved_path(Path::new("/var/run/noeio")),
            PathBuf::from("/var/run/noeio/ip_forward.orig")
        );
    }

    /// Needs root; run with `--ignored` in the privileged container.
    #[test]
    #[ignore]
    fn enable_then_restore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("noeio-fwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Force a known baseline (the container defaults to 1, which would
        // make the test vacuous).
        write(false).unwrap();
        assert!(!read().unwrap());

        assert!(enable(&dir).unwrap());
        assert!(read().unwrap());
        assert_eq!(std::fs::read_to_string(saved_path(&dir)).unwrap(), "0");
        // Second enable: nothing to change, original preserved.
        assert!(!enable(&dir).unwrap());
        assert_eq!(std::fs::read_to_string(saved_path(&dir)).unwrap(), "0");

        assert!(restore(&dir).unwrap());
        assert!(!read().unwrap());
        assert!(!saved_path(&dir).exists());
        assert!(!restore(&dir).unwrap(), "nothing left to restore");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
