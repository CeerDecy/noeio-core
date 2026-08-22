use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinSet;

use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};

use crate::config;
use crate::config::DerperInfo;

const U64_UNSET: u64 = u64::MAX;
const PROBE_INTERVAL: Duration = Duration::from_secs(20);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROBE_MISSES: u32 = 3;
pub const TS_LEN: usize = 8;

async fn resolve_addr(address: &str) -> Option<SocketAddr> {
    let addrs = match tokio::net::lookup_host(address).await {
        Ok(iter) => iter.collect::<Vec<SocketAddr>>(),
        Err(e) => {
            tracing::warn!(%address, error = %e, "derper: DNS resolution failed");
            return None;
        }
    };
    addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first().copied())
}

#[derive(Debug, Clone)]
pub struct ResolvedDerper {
    pub address: String,
    pub token: String,
    pub addr: SocketAddr,
    pub rtt_ms: Option<u64>,
}

pub struct DerperEntry {
    pub info: DerperInfo,
    pub addr: Option<SocketAddr>,
    rtt_ms: Arc<AtomicU64>,
    last_ping_ts: Arc<AtomicU64>,
    pong_tx: mpsc::Sender<u64>,
    _probe: JoinSet<()>,
}

impl DerperEntry {
    pub async fn new(
        info: DerperInfo,
        socket: Arc<UdpSocket>,
        probe_done_tx: mpsc::Sender<()>,
    ) -> Self {
        let addr = resolve_addr(&info.address).await;
        let rtt_ms = Arc::new(AtomicU64::new(U64_UNSET));
        let last_ping_ts = Arc::new(AtomicU64::new(U64_UNSET));
        let (pong_tx, pong_rx) = mpsc::channel(1);

        let mut tasks = JoinSet::new();
        if let Some(addr) = addr {
            tasks.spawn(Self::probe_loop(
                info.address.clone(),
                addr,
                socket,
                rtt_ms.clone(),
                last_ping_ts.clone(),
                pong_rx,
                probe_done_tx,
            ));
        }

        Self { info, addr, rtt_ms, last_ping_ts, pong_tx, _probe: tasks }
    }

    pub fn rtt(&self) -> Option<Duration> {
        match self.rtt_ms.load(Ordering::Acquire) {
            U64_UNSET => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    fn resolved(&self) -> Option<ResolvedDerper> {
        Some(ResolvedDerper {
            address: self.info.address.clone(),
            token: self.info.token.clone(),
            addr: self.addr?,
            rtt_ms: match self.rtt_ms.load(Ordering::Acquire) {
                U64_UNSET => None,
                ms => Some(ms),
            },
        })
    }

    pub fn on_pong(&self, echo_ts: u64) {
        let sent = self.last_ping_ts.load(Ordering::Acquire);
        if sent == U64_UNSET || echo_ts != sent {
            return;
        }
        let _ = self.pong_tx.try_send(echo_ts);
    }

    async fn probe_loop(
        address: String,
        addr: SocketAddr,
        socket: Arc<UdpSocket>,
        rtt_ms: Arc<AtomicU64>,
        last_ping_ts: Arc<AtomicU64>,
        mut pong_rx: mpsc::Receiver<u64>,
        probe_done_tx: mpsc::Sender<()>,
    ) {
        let mut misses: u32 = 0;

        loop {
            let base = Instant::now();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            last_ping_ts.store(ts, Ordering::Release);
            while pong_rx.try_recv().is_ok() {}

            let packet = NoeioPacket::new(
                PacketHeader {
                    packet_type: NoeioPacketType::TunnelPing,
                    peer_id: 0,
                    port: 0,
                },
                &ts.to_be_bytes(),
            );

            if let Err(e) = socket.send_to(&packet.inner, addr).await {
                tracing::debug!(%address, error = %e, "derper probe: send failed");
                Self::record_miss(&address, &mut misses, &rtt_ms, &probe_done_tx);
                tokio::time::sleep(PROBE_INTERVAL).await;
                continue;
            }

            match tokio::time::timeout(PROBE_TIMEOUT, pong_rx.recv()).await {
                Ok(Some(echo)) => {
                    if Self::accept_pong(echo, ts, base, &rtt_ms) {
                        misses = 0;
                        tracing::debug!(
                            %address,
                            rtt_ms = rtt_ms.load(Ordering::Acquire),
                            "derper probe ok"
                        );
                        let _ = probe_done_tx.try_send(());
                    } else {
                        tracing::debug!(%address, "derper probe: mismatched pong echo");
                        Self::record_miss(&address, &mut misses, &rtt_ms, &probe_done_tx);
                    }
                }
                Ok(None) => return,
                Err(_elapsed) => {
                    tracing::debug!(%address, "derper probe: pong timed out");
                    Self::record_miss(&address, &mut misses, &rtt_ms, &probe_done_tx);
                }
            }

            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }

    fn accept_pong(echo: u64, sent_ts: u64, base: Instant, rtt_ms: &AtomicU64) -> bool {
        if echo != sent_ts {
            return false;
        }
        rtt_ms.store(base.elapsed().as_millis() as u64, Ordering::Release);
        true
    }

    fn record_miss(
        address: &str,
        misses: &mut u32,
        rtt_ms: &AtomicU64,
        probe_done_tx: &mpsc::Sender<()>,
    ) {
        *misses = misses.saturating_add(1);
        if *misses == MAX_PROBE_MISSES {
            rtt_ms.store(U64_UNSET, Ordering::Release);
            let _ = probe_done_tx.try_send(());
            tracing::warn!(
                %address,
                misses = *misses,
                "derper probe: server unresponsive, dropping it from the ranking"
            );
        }
    }
}

pub struct DerperManager {
    servers: Arc<DashMap<String, Arc<DerperEntry>>>,
    by_addr: Arc<DashMap<SocketAddr, Arc<DerperEntry>>>,
    ordered: Arc<RwLock<Vec<Arc<DerperEntry>>>>,
    current: Arc<RwLock<Option<ResolvedDerper>>>,
    probe_done_tx: mpsc::Sender<()>,
    socket: Arc<UdpSocket>,
    _rank_task: JoinSet<()>,
}

impl DerperManager {
    pub async fn new(derper: config::Derper, socket: Arc<UdpSocket>) -> Self {
        let (probe_done_tx, probe_done_rx) = mpsc::channel(16);

        let servers: DashMap<String, Arc<DerperEntry>> = DashMap::new();
        let by_addr: DashMap<SocketAddr, Arc<DerperEntry>> = DashMap::new();
        let mut ordered = Vec::new();

        for s in derper.servers {
            let entry =
                Arc::new(DerperEntry::new(s.clone(), socket.clone(), probe_done_tx.clone()).await);
            if let Some(addr) = entry.addr {
                by_addr.insert(addr, entry.clone());
            }
            servers.insert(s.address.clone(), entry.clone());
            ordered.push(entry);
        }

        let initial = ordered.iter().find_map(|e| e.resolved());
        let current = Arc::new(RwLock::new(initial));
        let servers = Arc::new(servers);
        let by_addr = Arc::new(by_addr);
        let ordered = Arc::new(RwLock::new(ordered));

        let mut rank_task = JoinSet::new();
        rank_task.spawn(Self::rank_loop(
            ordered.clone(),
            current.clone(),
            probe_done_rx,
        ));

        Self { servers, by_addr, ordered, current, probe_done_tx, socket, _rank_task: rank_task }
    }

    pub fn dispatch_pong(&self, addr: SocketAddr, echo_ts: u64) -> bool {
        match self.by_addr.get(&addr) {
            Some(entry) => {
                entry.on_pong(echo_ts);
                true
            }
            None => false,
        }
    }

    async fn rank_loop(
        ordered: Arc<RwLock<Vec<Arc<DerperEntry>>>>,
        current: Arc<RwLock<Option<ResolvedDerper>>>,
        mut probe_done_rx: mpsc::Receiver<()>,
    ) {
        while probe_done_rx.recv().await.is_some() {
            while probe_done_rx.try_recv().is_ok() {}

            let guard = ordered.read().await;
            let best = guard
                .iter()
                .filter_map(|e| Some((e.rtt()?, e.resolved()?)))
                .min_by_key(|(rtt, _)| *rtt)
                .map(|(_, resolved)| resolved)
                .or_else(|| guard.iter().find_map(|e| e.resolved()));
            drop(guard);

            *current.write().await = best;
        }
    }

    pub async fn append_derper_server(&self, server: DerperInfo) {
        let entry = Arc::new(
            DerperEntry::new(server.clone(), self.socket.clone(), self.probe_done_tx.clone()).await,
        );
        if let Some(addr) = entry.addr {
            self.by_addr.insert(addr, entry.clone());
        }
        self.servers.insert(server.address.clone(), entry.clone());
        self.ordered.write().await.push(entry);
    }

    pub async fn remove_derper_server(&self, address: &str) -> bool {
        let Some((_, entry)) = self.servers.remove(address) else {
            return false;
        };
        if let Some(addr) = entry.addr {
            self.by_addr.remove(&addr);
        }
        self.ordered.write().await.retain(|e| e.info.address != address);
        let _ = self.probe_done_tx.try_send(());
        true
    }

    pub async fn list(&self) -> Vec<ResolvedDerper> {
        self.ordered
            .read()
            .await
            .iter()
            .filter_map(|e| e.resolved())
            .collect()
    }

    pub async fn current(&self) -> Option<ResolvedDerper> {
        self.current.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misses_below_threshold_keep_rtt() {
        // Transient loss (1-2 missed rounds) must not evict a server.
        let rtt = AtomicU64::new(42);
        let (tx, mut rx) = mpsc::channel(1);
        let mut misses = 0;

        for _ in 0..MAX_PROBE_MISSES - 1 {
            DerperEntry::record_miss("test:1", &mut misses, &rtt, &tx);
        }

        assert_eq!(rtt.load(Ordering::Acquire), 42);
        assert!(rx.try_recv().is_err(), "no re-rank below the threshold");
    }

    #[test]
    fn threshold_miss_invalidates_rtt_and_triggers_rerank() {
        let rtt = AtomicU64::new(42);
        let (tx, mut rx) = mpsc::channel(1);
        let mut misses = 0;

        for _ in 0..MAX_PROBE_MISSES {
            DerperEntry::record_miss("test:1", &mut misses, &rtt, &tx);
        }

        assert_eq!(rtt.load(Ordering::Acquire), U64_UNSET);
        assert!(rx.try_recv().is_ok(), "re-rank signalled at the threshold");
    }

    #[test]
    fn misses_past_threshold_do_not_retrigger() {
        let rtt = AtomicU64::new(42);
        let (tx, mut rx) = mpsc::channel(1);
        let mut misses = 0;

        for _ in 0..MAX_PROBE_MISSES {
            DerperEntry::record_miss("test:1", &mut misses, &rtt, &tx);
        }
        // Drain the threshold signal, then keep missing.
        rx.try_recv().unwrap();
        for _ in 0..3 {
            DerperEntry::record_miss("test:1", &mut misses, &rtt, &tx);
        }

        assert_eq!(rtt.load(Ordering::Acquire), U64_UNSET);
        assert!(rx.try_recv().is_err(), "already-unset RTT is not re-signalled");
    }

    #[test]
    fn mismatched_echo_is_rejected_without_touching_rtt() {
        let rtt = AtomicU64::new(42);
        let base = Instant::now();

        assert!(!DerperEntry::accept_pong(111, 222, base, &rtt));
        assert_eq!(rtt.load(Ordering::Acquire), 42, "rtt untouched on mismatch");

        assert!(DerperEntry::accept_pong(222, 222, base, &rtt));
        assert_ne!(rtt.load(Ordering::Acquire), 42, "rtt written on match");
    }

    /// A pong that arrives after its round timed out must not satisfy the next
    /// round: the new-timestamp store rejects late arrivals in `on_pong`, and
    /// the drain clears anything queued before the store.
    #[tokio::test]
    async fn stale_pong_cannot_leak_into_next_round() {
        let (pong_tx, mut pong_rx) = mpsc::channel(1);
        let entry = DerperEntry {
            info: DerperInfo::default(),
            addr: None,
            rtt_ms: Arc::new(AtomicU64::new(U64_UNSET)),
            last_ping_ts: Arc::new(AtomicU64::new(1000)), // round N's ts
            pong_tx,
            _probe: JoinSet::new(),
        };

        // Round N times out; its pong arrives late, during the sleep. The
        // echo matches last_ping_ts (not yet advanced), so it queues.
        entry.on_pong(1000);

        // Round N+1 begins: store the new ts, then drain — the probe_loop
        // order under test.
        entry.last_ping_ts.store(2000, Ordering::Release);
        while pong_rx.try_recv().is_ok() {}

        // A late pong arriving after the store is rejected by the echo check.
        entry.on_pong(1000);

        assert!(
            pong_rx.try_recv().is_err(),
            "no stale signal must survive into round N+1"
        );

        // The genuine round-N+1 pong still gets through.
        entry.on_pong(2000);
        assert_eq!(pong_rx.try_recv(), Ok(2000));
    }

    fn entry_with_addr(address: &str, addr: Option<SocketAddr>) -> DerperEntry {
        DerperEntry {
            info: DerperInfo {
                address: address.to_string(),
                token: "tok".to_string(),
            },
            addr,
            rtt_ms: Arc::new(AtomicU64::new(U64_UNSET)),
            last_ping_ts: Arc::new(AtomicU64::new(0)),
            pong_tx: mpsc::channel(1).0,
            _probe: JoinSet::new(),
        }
    }

    #[test]
    fn resolved_flattens_config_and_skips_unresolved() {
        // A hostname that resolved: callers get the wire address alongside the
        // original config string, so reports reach it and the CLI can still
        // show what was configured.
        let ok = entry_with_addr("derp.example.com:3478", Some("10.0.0.1:3478".parse().unwrap()));
        let resolved = ok.resolved().expect("resolved entry yields a value");
        assert_eq!(resolved.address, "derp.example.com:3478");
        assert_eq!(resolved.token, "tok");
        assert_eq!(resolved.addr, "10.0.0.1:3478".parse().unwrap());

        // DNS failed: no wire address, so it must not reach a caller that is
        // about to send — this is what kept hostname derpers from getting
        // reports back when the report loop parsed the string itself.
        assert!(entry_with_addr("broken.invalid:3478", None).resolved().is_none());
    }
}
