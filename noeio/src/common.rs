pub mod idle_guard;
pub mod stun;

use std::path::PathBuf;

/// Directory for state that must not outlive a boot: the reconciler's
/// installed-route mirror and the saved sysctl originals. On Linux this is
/// tmpfs, so a reboot — after which none of that state is valid anyway —
/// starts clean. `NOEIO_RUN_DIR` overrides it (tests, unprivileged runs).
pub fn run_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("NOEIO_RUN_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(unix)]
    {
        PathBuf::from("/var/run/noeio")
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("noeio")
            .join("run")
    }
}
