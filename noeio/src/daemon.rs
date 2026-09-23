pub mod derper;
pub mod nat;
pub mod nic;
pub mod peer;
pub mod reconciler;
pub mod router;
pub mod routes;
pub mod stun;

use crate::common;
use crate::config::Config;
use crate::daemon::derper::DerperManager;
use crate::daemon::nic::NicManager;
use crate::daemon::peer::Peer;
use crate::daemon::reconciler::{PeerRoutes, Reconciler, RouteKey};
use crate::daemon::router::Router;
use crate::daemon::routes::{ConsumerPolicy, Decision, Protected};
use crate::daemon::stun::StunManager;
use crate::interface::virtual_nic::VirtualNic;
use crate::tunnel::session::TunnOutput;
use bytecodec::{DecodeExt, EncodeExt, Error as BytecodecError};
use dashmap::DashMap;
use noeio_common::host_info;
use noeio_common::host_info::{HostInfo, NatType, PeerId, PeerInfo};
use noeio_common::packet::report::ReportPayload;
use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv4Packet;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use stun_codec::rfc5389::Attribute;
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::ChangeRequest;
use stun_codec::{Message, MessageDecoder, MessageEncoder};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tun::DeviceReader;

const MAX_BUFFER_SIZE: usize = 2048;
/// Headroom for the WireGuard codec: data packets grow by 32 bytes over the
/// plaintext, and protocol packets (handshake init = 148 bytes) must also fit.
const WG_BUFFER_SIZE: usize = MAX_BUFFER_SIZE + 160;
const STUN_PROBE_INTERVAL_MINS: u64 = 10;
/// WireGuard expects its timer state machine to be driven roughly every 250ms.
const WG_TIMER_TICK_MILLIS: u64 = 250;

pub struct NoeioDaemon {
    pub nics: NicManager,
    pub udp: Arc<UdpSocket>,
    pub config: Config,
    pub derper: DerperManager,
    pub stun: StunManager,
    pub host_info: Mutex<Option<HostInfo>>,
    pub router: Router,
    pub reconciler: Reconciler,
    /// Subnets this node advertises. Already validated (see
    /// [`routes::validate_advertisement`]); on a consumer-only platform this
    /// is always empty, which is what keeps such a node out of the broadcast
    /// path. Behind a std lock: read on every report, written on config /
    /// RPC changes only.
    pub advertised: std::sync::RwLock<Vec<Ipv4Cidr>>,
    /// Addresses no advertised CIDR may cover (derper / STUN), resolved at
    /// boot. Used when validating runtime advertisements.
    pub control_plane: Vec<IpAddr>,
    /// The last consumer-side decisions, for `route list` (FR-7.4).
    pub decisions: std::sync::RwLock<Vec<Decision>>,
    /// Packets dropped by the AllowedIPs check, per source peer (O-3).
    pub allowed_ips_drops: DashMap<PeerId, u64>,
    /// Forwarding / SNAT currently applied on this (Linux) advertiser.
    pub nat_state: std::sync::Mutex<nat::NatState>,
    pub task: JoinSet<()>,
}

impl NoeioDaemon {
    pub async fn new(udp: UdpSocket, cfg: Config) -> Arc<Self> {
        let udp = Arc::new(udp);
        let derper = DerperManager::new(cfg.derper.clone(), udp.clone()).await;
        let stun = StunManager::from(cfg.stun.clone());
        let control_plane = routes::resolve_control_plane(&cfg).await;
        // `main` has already validated and normalized these; a parse failure
        // here would be a bug, not user input.
        let advertised: Vec<Ipv4Cidr> = cfg
            .router
            .advertise_routes
            .iter()
            .filter_map(|c| c.parse().ok())
            .collect();
        let daemon = Arc::new(Self {
            nics: NicManager::new(),
            udp,
            derper,
            stun,
            config: cfg,
            host_info: Mutex::new(None),
            router: Router::new(),
            reconciler: Reconciler::new(Some(reconciler::default_state_file())),
            advertised: std::sync::RwLock::new(advertised),
            control_plane,
            decisions: Default::default(),
            allowed_ips_drops: DashMap::new(),
            nat_state: Default::default(),
            task: JoinSet::new(),
        });

        process_inbound(daemon.clone());

        stun_probe(daemon.clone());

        register_host_info(daemon.clone());

        wg_timers(daemon.clone());

        reconciler::spawn(daemon.clone());
        daemon
    }

    /// Subnets this node currently advertises.
    pub fn advertised_routes(&self) -> Vec<Ipv4Cidr> {
        self.advertised.read().unwrap().clone()
    }

    /// Replace the advertised set (already validated by the caller) and make
    /// the change visible: every local `PeerInfo` gets the new list and
    /// `HostInfo.resource_version` is bumped, because the derper dedupes
    /// reports by that version and would otherwise drop the update on the
    /// floor (FR-1.6). Also re-runs the consumer decisions, since what we
    /// advertise ourselves is one of their inputs.
    pub async fn set_advertised(&self, routes: Vec<Ipv4Cidr>) {
        {
            let mut current = self.advertised.write().unwrap();
            if *current == routes {
                return;
            }
            *current = routes.clone();
        }
        tracing::info!(routes = ?routes, "advertised routes updated");
        if let Some(host) = self.host_info.lock().await.as_mut() {
            for peer in &mut host.peers {
                peer.advertised_routes = routes.clone();
            }
            host.resource_version = host_info::now_version().max(host.resource_version + 1);
        }
        self.reconciler.notify();
    }

    /// The consumer-side policy for [`routes::decide`], from config plus what
    /// this node itself advertises and where its physical interfaces are.
    fn consumer_policy(&self) -> ConsumerPolicy {
        let overlay_ips = self.nics.ips();
        ConsumerPolicy {
            accept_routes: self.config.router.accept_routes,
            local_lans: routes::local_lans(&overlay_ips),
            self_advertised: self.advertised_routes(),
            protected: Protected {
                overlay_ips,
                control_plane: self.control_plane.clone(),
            },
        }
    }

    /// Re-run the consumer decisions over every peer's advertisements and
    /// refresh the router's subnet table with the accepted ones. Called on
    /// every router change before the reconciler runs, so the LPM table used
    /// by `process_outbound` and the kernel routes always come from the same
    /// decision. Logs each newly rejected advertisement (FR-2.6).
    pub fn refresh_subnets(&self) {
        let peers = self.router.peers();
        let mut advertised: Vec<(PeerId, Ipv4Cidr)> = Vec::new();
        for peer in &peers {
            let info = peer.info();
            for cidr in info.advertised_routes {
                advertised.push((info.peer_id, cidr));
            }
        }
        let decisions = routes::decide(&self.consumer_policy(), &advertised);

        let previous = self.decisions.read().unwrap().clone();
        for d in &decisions {
            let was = previous
                .iter()
                .find(|p| p.peer_id == d.peer_id && p.cidr == d.cidr)
                .map(|p| p.rejected);
            if was != Some(d.rejected) {
                match d.rejected {
                    None => {
                        tracing::info!(peer_id = d.peer_id, cidr = %d.cidr, "subnet route accepted")
                    }
                    Some(why) => {
                        tracing::warn!(peer_id = d.peer_id, cidr = %d.cidr, %why, "subnet route rejected")
                    }
                }
            }
        }
        for p in &previous {
            if !decisions
                .iter()
                .any(|d| d.peer_id == p.peer_id && d.cidr == p.cidr)
            {
                tracing::info!(peer_id = p.peer_id, cidr = %p.cidr, "subnet route withdrawn");
            }
        }

        let accepted: Vec<(Ipv4Cidr, PeerId)> = decisions
            .iter()
            .filter(|d| d.rejected.is_none())
            .map(|d| (d.cidr, d.peer_id))
            .collect();
        self.router.set_subnets(accepted);
        *self.decisions.write().unwrap() = decisions;
    }

    /// The routes every known peer contributes, as plain data for
    /// [`reconciler::desired`]. Subnets come from the router's accepted table
    /// (see [`Self::refresh_subnets`]), so a withdrawn or rejected route is
    /// simply not in the snapshot and the reconciler deletes it (FR-2.5).
    pub fn route_snapshot(&self) -> Vec<PeerRoutes> {
        let subnets = self.router.subnets();
        self.router
            .peers()
            .into_iter()
            .map(|peer| {
                let info = peer.info();
                PeerRoutes {
                    nic: peer.local_peer_id(),
                    peer_id: info.peer_id,
                    ip: info.noeio_ip,
                    subnets: subnets
                        .iter()
                        .filter(|(_, exit)| *exit == info.peer_id)
                        .map(|(cidr, _)| *cidr)
                        .collect(),
                }
            })
            .collect()
    }

    fn ifindex_of(&self, nic: PeerId) -> Option<u32> {
        self.nics.get(&nic).map(|nic| nic.tun_index)
    }

    /// One reconciler pass against the current router state.
    pub async fn reconcile_routes(&self) -> usize {
        self.refresh_subnets();
        let desired = reconciler::desired(&self.nics.peers(), &self.route_snapshot());
        self.reconciler
            .reconcile(&desired, |nic| self.ifindex_of(nic))
            .await
    }

    /// Fold one `SyncRoute` into the router. `local_peer_id` is our own id in
    /// the peer's network (the SyncRoute header addresses us). Returns whether
    /// the router changed, i.e. whether the reconciler should run.
    pub fn apply_sync_route(&self, peer: PeerInfo, local_peer_id: PeerId) -> bool {
        if peer.withdrawn {
            // Tombstone from the derper: the peer's reports stopped. Drop it
            // and everything it contributed; the reconciler removes the
            // routes. This is the only liveness signal we act on — silence
            // alone never is (FR-8.6).
            return match self.router.remove_by_peer_id(&peer.peer_id) {
                Some(_) => {
                    tracing::info!(
                        peer_id = peer.peer_id,
                        ip = %peer.noeio_ip,
                        resource_version = peer.resource_version,
                        "peer withdrawn by derper"
                    );
                    true
                }
                None => false,
            };
        }
        match self.router.get(&peer.noeio_ip) {
            Some(existing) => {
                let current_version = existing.info().resource_version;
                if peer.resource_version > current_version {
                    let previous = existing.info().advertised_routes;
                    if previous != peer.advertised_routes {
                        tracing::info!(
                            peer_id = peer.peer_id,
                            resource_version = peer.resource_version,
                            routes = ?peer.advertised_routes,
                            "peer advertised routes changed"
                        );
                    }
                    self.router.update_info(&existing, peer, local_peer_id);
                    true
                } else {
                    tracing::debug!(
                        peer = %peer.peer_id,
                        incoming = peer.resource_version,
                        current = current_version,
                        "skipping stale SyncRoute"
                    );
                    false
                }
            }
            None => {
                self.router
                    .insert(Peer::new(peer, self.udp.clone(), local_peer_id));
                true
            }
        }
    }

    /// Best-effort clean exit: remove every route we installed. The kernel
    /// would reclaim them with the TUN anyway; doing it explicitly keeps the
    /// state file truthful and covers platforms where that is unverified.
    pub async fn shutdown(self: &Arc<Self>) {
        let empty: std::collections::BTreeSet<RouteKey> = Default::default();
        let removed = self
            .reconciler
            .reconcile(&empty, |nic| self.ifindex_of(nic))
            .await;
        tracing::info!(removed, "routes removed on shutdown");
        // Forwarding and the nftables table do not die with the process, so
        // this is the one place they get removed on a clean exit.
        self.advertised.write().unwrap().clear();
        nat::converge(self).await;
    }

    pub async fn add_peer(&self, peer: host_info::PeerInfo) -> Result<(), &'static str> {
        let mut info = self.host_info.lock().await;
        match info.as_mut() {
            Some(host) => {
                if let Some(existing) = host.peers.iter_mut().find(|p| p.noeio_ip == peer.noeio_ip)
                {
                    existing.peer_id = peer.peer_id;
                } else {
                    host.peers.push(peer);
                }
                Ok(())
            }
            None => Err("host info not initialized"),
        }
    }

    pub async fn register_nic(
        &self,
        state: Arc<NoeioDaemon>,
        nic: VirtualNic,
        reader: DeviceReader,
        network: String,
    ) -> Result<(), String> {
        let peer_id = host_info::new_peer_id();
        let peer = host_info::PeerInfo::new(peer_id, nic.ip, &network)
            .map_err(|err| format!("failed to create peer: {}", err))?
            .with_advertised_routes(self.advertised_routes());

        tracing::info!(peer_id = %peer_id, "creating virtual nic {}", nic.ip);

        self.nics.register(peer_id, nic);
        // A new nic is an egress for routes (and, on an advertiser, the TUN
        // the NAT rules name); converge right away rather than on the tick.
        self.reconciler.notify();
        self.add_peer(peer).await?;
        process_outbound(state, reader);
        Ok(())
    }

    /// Send one tunnel datagram (WG ciphertext or protocol traffic) to `peer`,
    /// choosing the path and the envelope together:
    ///
    /// - direct: a `Delivery` stamped with our own id in the peer's network,
    ///   so the receiver can resolve us (and our tunnel session) immediately;
    /// - relay: a `Forward` naming the destination peer; the derper rewrites
    ///   it into a `Delivery` stamped with our id, which it authenticates from
    ///   its own peer table rather than trusting the packet.
    pub async fn send_to_peer(&self, peer: &Peer, datagram: &[u8]) -> std::io::Result<usize> {
        if let Some(nat_addr) = peer.address() {
            let header = PacketHeader {
                packet_type: NoeioPacketType::Delivery,
                peer_id: peer.local_peer_id(),
                port: 0,
            };
            let bytes: Vec<u8> = NoeioPacket::new(header, datagram).into();
            tracing::info!(
                peer_id = peer.info().peer_id,
                %nat_addr,
                "send_to_peer: direct path",
            );
            return self.udp.send_to(&bytes, nat_addr).await;
        }

        let derper = match self.derper.current().await {
            None => {
                tracing::error!("DERPER: No server selected");
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "No server selected",
                ));
            }
            Some(derper) => derper,
        };

        let header = PacketHeader {
            packet_type: NoeioPacketType::Forward,
            peer_id: peer.info().peer_id,
            port: 0,
        };
        let bytes: Vec<u8> = NoeioPacket::new(header, datagram).into();
        tracing::info!(
            peer_id = peer.info().peer_id,
            derper = %derper.address,
            nat_addr = "none",
            "send_to_peer: relay path",
        );
        self.udp.send_to(&bytes, derper.addr).await
    }
}

pub fn process_outbound(state: Arc<NoeioDaemon>, mut reader: DeviceReader) {
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_BUFFER_SIZE];
        loop {
            match reader.read(&mut buf).await {
                Ok(n) => {
                    // TODO: macOS utun prefixes every packet with 4 bytes of
                    // protocol family (AF_INET = 2). Strip it here so the rest
                    // of the pipeline sees raw IPv4. Move this into a NicReader
                    // wrapper once the bug is confirmed end-to-end.
                    #[cfg(target_os = "macos")]
                    let ip_bytes: &[u8] = if n >= 4 { &buf[4..n] } else { continue };
                    #[cfg(not(target_os = "macos"))]
                    let ip_bytes: &[u8] = &buf[..n];

                    tracing::debug!("received outbound packet: {:?}", ip_bytes);

                    if let Ok(ipv4) = Ipv4Packet::new_checked(ip_bytes) {
                        let dst_ip = IpAddr::from(ipv4.dst_addr());

                        // Exact host route first, then longest accepted
                        // subnet prefix. A miss is routine with subnet routes
                        // (broadcasts, scans of a covered range that we
                        // don't route), so it is not an error.
                        let peer = match state.router.lookup(&dst_ip) {
                            None => {
                                tracing::debug!(%dst_ip, "no route for outbound packet");
                                continue;
                            }
                            Some(peer) => peer,
                        };

                        let mut wg_buf = [0u8; WG_BUFFER_SIZE];
                        match peer.codec().encapsulate(ip_bytes, &mut wg_buf) {
                            TunnOutput::ToPeer(datagram) => {
                                if let Err(err) = state.send_to_peer(&peer, datagram).await {
                                    tracing::error!("Failed to send packet: {}", err);
                                }
                            }
                            TunnOutput::Err(err) => {
                                tracing::warn!(
                                    peer_id = peer.info().peer_id,
                                    "encapsulate failed: {}",
                                    err
                                );
                            }
                            // Consumed means the packet was queued while the
                            // handshake is in flight; encapsulating plaintext
                            // never produces ToNic.
                            _ => {}
                        }
                    }
                }
                Err(err) => {
                    eprintln!("err: {}", err);
                }
            }
        }
    });
}

/// The local (LAN) socket addresses to advertise as direct-path candidates.
///
/// Deliberately conservative: only the *primary* interface — the one the OS
/// routes toward the derper — is reported, paired with our UDP `port`.
/// Secondary interfaces stay unadvertised until a config option exists to opt
/// them in; when it does, this function is where it plugs in (the wire format
/// and the receiving side already handle any number of addresses).
///
/// The probe socket never sends a packet: UDP `connect` only asks the OS to
/// resolve the route. Returns an empty list when the route can't be resolved
/// or the resolved IP is unusable as an underlay candidate — loopback (e.g. a
/// local dev derper) or one of our own overlay nics (`overlay_ips`), since
/// traffic to an overlay address goes *through* the tunnel.
fn report_local_addrs(port: u16, derper: SocketAddr, overlay_ips: &[IpAddr]) -> Vec<SocketAddr> {
    let primary = || -> Option<IpAddr> {
        let bind_addr = if derper.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let probe = std::net::UdpSocket::bind(bind_addr).ok()?;
        probe.connect(derper).ok()?;
        Some(probe.local_addr().ok()?.ip())
    };
    match primary() {
        Some(ip) if !ip.is_loopback() && !overlay_ips.contains(&ip) => {
            vec![SocketAddr::new(ip, port)]
        }
        _ => Vec::new(),
    }
}

fn register_host_info(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(core::time::Duration::from_secs(10)).await;

            let derpers = daemon.derper.list().await;
            if derpers.is_empty() {
                tracing::warn!(
                    "report skipped: no derper server with a resolved address, check [derper] config"
                );
                continue;
            }

            let Some(host_info) = daemon.host_info.lock().await.clone() else {
                tracing::warn!(
                    "report skipped: host_info not initialized, waiting for a STUN response"
                );
                continue;
            };

            if daemon.nics.peers().is_empty() {
                tracing::warn!("report skipped: no nic registered");
                continue;
            }

            // TODO
            let peer_id = daemon.nics.peers()[0];

            for derper in &derpers {
                let addr = derper.addr;

                // Refresh the LAN candidate on every report: the primary route
                // can change, and the report is what keeps the derper's view
                // current. The candidate lives on each PeerInfo (the per-network
                // identity the derper broadcasts); the host-level copy is only
                // kept for derpers that predate per-peer local_addrs.
                let mut host_info = host_info.clone();
                match daemon.udp.local_addr() {
                    Ok(local) => {
                        let local_addrs =
                            report_local_addrs(local.port(), addr, &daemon.nics.ips());
                        for peer in &mut host_info.peers {
                            peer.local_addrs = local_addrs.clone();
                        }
                        host_info.local_addrs = local_addrs;
                    }
                    Err(err) => {
                        tracing::warn!("report: failed to read local udp port: {}", err);
                    }
                }

                let payload = ReportPayload::new(derper.token.clone(), host_info).to_bytes();
                let mut header = PacketHeader::default();

                tracing::info!(peer = %peer_id, "peer id");

                header.packet_type = NoeioPacketType::Report;
                header.peer_id = peer_id;

                let packet: Vec<u8> = NoeioPacket::new(header, &payload).into();

                if let Err(err) = daemon.udp.send_to(&packet, addr).await {
                    tracing::error!(%derper.address, "failed to send host info: {}", err);
                } else {
                    tracing::info!("host info sent to {}", addr);
                }
            }
        }
    });
}

async fn send_stun_probe(daemon: &Arc<NoeioDaemon>) -> io::Result<()> {
    let Some(stun_server) = daemon.stun.pick_server() else {
        return Ok(());
    };

    let addrs: Vec<_> = lookup_host(stun_server).await?.collect();

    let server_addr = addrs
        .iter()
        .copied()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "failed to resolve STUN server"))?;

    let tid = common::stun::generate_tid();
    let message: stun_codec::Message<ChangeRequest> =
        stun_codec::Message::new(stun_codec::MessageClass::Request, BINDING, tid);

    let mut encoder = MessageEncoder::new();
    let bytes = encoder
        .encode_into_bytes(message)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    daemon.udp.send_to(&bytes, server_addr).await?;

    Ok(())
}

pub fn stun_probe(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        if let Err(err) = send_stun_probe(&daemon).await {
            tracing::error!("stun probe failed: {}", err);
        }

        loop {
            if let Err(err) = send_stun_probe(&daemon).await {
                tracing::error!("stun probe failed: {}", err);
            }

            tokio::time::sleep(std::time::Duration::from_mins(STUN_PROBE_INTERVAL_MINS)).await;
        }
    });
}

pub fn process_inbound(state: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_BUFFER_SIZE];
        loop {
            match state.udp.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    // A datagram that fills the buffer was likely truncated by
                    // `recv_from`; a clipped ciphertext would only fail
                    // decryption later, so drop it while the cause is visible.
                    if n >= MAX_BUFFER_SIZE {
                        tracing::warn!(
                            source = %addr,
                            "dropping datagram: fills the {}-byte buffer, likely truncated",
                            MAX_BUFFER_SIZE
                        );
                        continue;
                    }
                    if let Ok(packet) = NoeioPacket::try_from(&buf[..n])
                        && let Some(header) = packet.parse_header()
                    {
                        match header.packet_type {
                            NoeioPacketType::Ping => {}
                            NoeioPacketType::Forward => {
                                // Forward is derper-bound ("relay this to the
                                // peer it names"); a node receiving one means
                                // the sender speaks the old plaintext protocol.
                                tracing::warn!(
                                    source = %addr,
                                    "dropping forward packet: nodes only accept delivery"
                                );
                            }
                            NoeioPacketType::Delivery => {
                                // Stamped with the *sender's* peer id — by the
                                // derper on the relay path, by the sender
                                // itself on the direct path (a forged id is
                                // harmless: the wrong session fails to
                                // decrypt).
                                let Some(payload) = packet.payload() else {
                                    continue;
                                };
                                // `get_by_peer_id` clones the `Arc` out, so no
                                // router guard is held across the await below.
                                let peer = match state.router.get_by_peer_id(&header.peer_id) {
                                    Some(peer) => peer,
                                    None => {
                                        tracing::warn!(
                                            source = %addr,
                                            sender = header.peer_id,
                                            "dropping delivery from unknown peer"
                                        );
                                        continue;
                                    }
                                };
                                handle_delivery(&state, &peer, payload, addr).await;
                            }
                            NoeioPacketType::SyncRoute => {
                                // Route pushes are only trusted from the derper
                                // we are configured to talk to; drop spoofed ones.
                                let derper_ip = state.derper.current().await.map(|d| d.addr.ip());
                                if derper_ip != Some(addr.ip()) {
                                    tracing::warn!(
                                        source = %addr,
                                        "dropping SyncRoute from unexpected source"
                                    );
                                    continue;
                                }

                                if let Some(payload) = packet.payload() {
                                    match PeerInfo::try_from(payload) {
                                        Ok(peer) => {
                                            // `header.peer_id` is our own id in
                                            // this peer's network (SyncRoute is
                                            // addressed to us); the session stamps
                                            // it into the signalling it sends.
                                            // Only the in-memory router changes here;
                                            // the reconciler owns the kernel table
                                            // and is woken to converge it.
                                            if state.apply_sync_route(peer, header.peer_id) {
                                                state.reconciler.notify();
                                            }
                                        }
                                        Err(err) => {
                                            tracing::error!(
                                                "failed to parse SyncRoute payload: {}",
                                                err
                                            );
                                        }
                                    };
                                }
                            }
                            NoeioPacketType::Report => {}
                            // Seq/Ack/TunnelPing are peer-to-peer signalling;
                            // route them to the peer's UdpTunnelSession.
                            NoeioPacketType::Seq
                            | NoeioPacketType::Ack
                            | NoeioPacketType::TunnelPing => {
                                dispatch_signalling(&state, &header, &buf[..n], addr).await;
                            }
                            NoeioPacketType::TunnelPong => {
                                let echo_ts = packet
                                    .payload()
                                    .and_then(|p| p.get(..derper::TS_LEN))
                                    .and_then(|b| b.try_into().ok())
                                    .map(u64::from_be_bytes);

                                let claimed = match echo_ts {
                                    Some(ts) => state.derper.dispatch_pong(addr, ts),
                                    None => false,
                                };
                                if !claimed && header.peer_id != 0 {
                                    dispatch_signalling(&state, &header, &buf[..n], addr).await;
                                }
                            }
                        }
                        continue;
                    }

                    // Handle STUN response
                    let mut decoder = MessageDecoder::<Attribute>::new();
                    if let Ok(response) = decoder.decode_from_bytes(&buf[..n]) {
                        let response = response.map_err(BytecodecError::from).unwrap();

                        let addr = parse_mapped_addr(response)
                            .ok_or_else(|| "failed to parse mapped address".to_string())
                            .unwrap();

                        {
                            let mut info = state.host_info.lock().await;
                            let new_info = HostInfo::new(addr);
                            match info.as_mut() {
                                Some(existing) => {
                                    let nat_type = if existing.nat_addr == new_info.nat_addr {
                                        NatType::Other
                                    } else {
                                        NatType::Symmetric
                                    };
                                    tracing::info!(
                                        %nat_type,
                                        prev = ?existing.nat_addr,
                                        curr = ?new_info.nat_addr,
                                        "determined NAT type",
                                    );
                                    existing.nat_type = nat_type;
                                    existing.nat_addr = new_info.nat_addr;
                                    existing.resource_version = new_info.resource_version;
                                    existing.hostname = new_info.hostname;
                                }
                                None => {
                                    *info = Some(new_info);
                                }
                            }
                        }
                        tracing::info!("Received NAT address: {} from stun server", addr);
                        continue;
                    }

                    tracing::info!("unsupported packet: {:?}", &buf[..n]);
                }
                Err(err) => {
                    tracing::error!("UDP recv error: {}", err);
                }
            }
        }
    });
}

/// Decrypt one inbound `Delivery` datagram from `peer` and act on everything
/// the codec produces: plaintext goes to the nic we registered in this peer's
/// network, protocol replies (handshake responses, keepalives, queued data
/// packets) go back to the peer.
async fn handle_delivery(state: &Arc<NoeioDaemon>, peer: &Peer, payload: &[u8], src: SocketAddr) {
    let info = peer.info();
    let codec = peer.codec();
    let mut input: &[u8] = payload;
    loop {
        let mut buf = [0u8; WG_BUFFER_SIZE];
        match codec.decapsulate(Some(src.ip()), input, &mut buf) {
            TunnOutput::ToNic(plaintext, inner_src) => {
                // Anti-spoofing with WireGuard AllowedIPs semantics: the
                // decrypted packet must come from the peer's own virtual IP
                // or from inside a subnet the peer advertises (a subnet
                // router forwards replies that carry the LAN host's address).
                // Anything else is dropped. Counted per peer and logged only
                // on the first drop and every 1000th after that, so one
                // misconfigured peer can't flood the log.
                if let Some(ip) = inner_src
                    && !Router::allowed_source(&info, ip)
                {
                    let mut count = state.allowed_ips_drops.entry(info.peer_id).or_insert(0);
                    *count += 1;
                    if *count == 1 || count.is_multiple_of(1000) {
                        tracing::warn!(
                            peer_id = info.peer_id,
                            %ip,
                            dropped = *count,
                            "dropping packet: inner source not in peer's allowed IPs"
                        );
                    }
                    break;
                }
                write_to_nic(state, peer.local_peer_id(), plaintext).await;
                break;
            }
            TunnOutput::ToPeer(reply) => {
                if let Err(err) = state.send_to_peer(peer, reply).await {
                    tracing::error!("failed to send tunnel reply: {}", err);
                    break;
                }
                // A repeated call with an empty datagram flushes anything else
                // the codec queued behind this reply.
                input = &[];
            }
            TunnOutput::Consumed => break,
            TunnOutput::Err(err) => {
                tracing::warn!(peer_id = info.peer_id, "decapsulate failed: {}", err);
                break;
            }
        }
    }
}

/// Write one plaintext IP packet to the nic registered under `nic_id`.
async fn write_to_nic(state: &Arc<NoeioDaemon>, nic_id: PeerId, packet: &[u8]) {
    let Some(mut nic) = state.nics.get_mut(&nic_id) else {
        tracing::error!("can't get nic for peer {}", nic_id);
        return;
    };

    // TODO: macOS utun requires a 4-byte AF_INET prefix on writes; the tun
    // crate (0.8.6) doesn't prepend it for us. Move this into a VirtualNic
    // wrapper once the bug is confirmed end-to-end.
    #[cfg(target_os = "macos")]
    let framed = {
        let mut framed = Vec::with_capacity(4 + packet.len());
        framed.extend_from_slice(&[0, 0, 0, 2]); // AF_INET, big-endian
        framed.extend_from_slice(packet);
        framed
    };
    #[cfg(target_os = "macos")]
    let packet: &[u8] = &framed;

    if let Err(err) = nic.writer.write(packet).await {
        tracing::error!("Failed to write to {} nic: {}", nic_id, err);
    }
}

/// Drive every peer codec's clock: rekeys, handshake retransmissions, and
/// keepalives all originate here, ticking at [`WG_TIMER_TICK_MILLIS`].
fn wg_timers(daemon: Arc<NoeioDaemon>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(core::time::Duration::from_millis(WG_TIMER_TICK_MILLIS));
        loop {
            interval.tick().await;
            // Snapshot the peers so no router guard is held across the awaits
            // below.
            for peer in daemon.router.peers() {
                let mut buf = [0u8; WG_BUFFER_SIZE];
                match peer.codec().update_timers(&mut buf) {
                    TunnOutput::ToPeer(datagram) => {
                        if let Err(err) = daemon.send_to_peer(&peer, datagram).await {
                            tracing::error!("failed to send timer packet: {}", err);
                        }
                    }
                    // Idle tunnels report expiry here on every tick; that's
                    // state, not an event worth logging above trace.
                    TunnOutput::Err(err) => {
                        tracing::trace!(peer_id = peer.info().peer_id, "update_timers: {}", err);
                    }
                    _ => {}
                }
            }
        }
    });
}

/// Route a session's signalling datagram (Seq/Ack/TunnelPing/TunnelPong) to
/// the peer it names.
///
/// Resolves the peer by `header.peer_id` and hands the raw datagram to its
/// `UdpTunnelSession` inbound channel; the session's `dispatch` task owns the
/// actual handling (nonce-matched handshake, Ack/Pong replies, RTT and
/// liveness stamps).
///
/// `get_by_peer_id` clones the `Arc` out, so no router shard guard is held
/// across the `inbound` await.
async fn dispatch_signalling(
    state: &Arc<NoeioDaemon>,
    header: &PacketHeader,
    datagram: &[u8],
    src: SocketAddr,
) {
    let Some(peer) = state.router.get_by_peer_id(&header.peer_id) else {
        tracing::warn!(
            peer_id = header.peer_id,
            "received signalling packet for unknown peer",
        );
        return;
    };

    if !peer.inbound(datagram.to_vec(), src).await {
        tracing::debug!(
            peer_id = header.peer_id,
            ?header.packet_type,
            "dropping signalling packet: peer has no live session",
        );
    }
}

fn parse_mapped_addr(response: Message<Attribute>) -> Option<SocketAddr> {
    for attr in response.attributes() {
        match attr {
            Attribute::MappedAddress(address) => return Some(address.address()),
            Attribute::XorMappedAddress(address) => return Some(address.address()),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use noeio_common::host_info::{HostInfo, PeerInfo, new_peer_id};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const SAMPLE_NET: &str = "550e8400-e29b-41d4-a716-446655440000";

    async fn test_daemon(host_info: Option<HostInfo>) -> NoeioDaemon {
        let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        NoeioDaemon {
            nics: NicManager::new(),
            udp: udp.clone(),
            config: Config::default(),
            derper: DerperManager::new(crate::config::Derper::default(), udp).await,
            stun: StunManager::from(crate::config::Stun::default()),
            host_info: Mutex::new(host_info),
            router: Router::new(),
            reconciler: Reconciler::default(),
            advertised: Default::default(),
            control_plane: Vec::new(),
            decisions: Default::default(),
            allowed_ips_drops: DashMap::new(),
            nat_state: Default::default(),
            task: JoinSet::new(),
        }
    }

    #[test]
    fn report_local_addrs_drops_loopback_primary() {
        // A loopback derper (local dev) resolves to a loopback source, which
        // is useless as a LAN candidate — nothing must be advertised.
        let derper = "127.0.0.1:3478".parse().unwrap();
        assert!(report_local_addrs(41641, derper, &[]).is_empty());
    }

    /// AC-14: a peer that stays silent after we learned it must keep its
    /// routes. The derper dedupes reports by `resource_version`, so a healthy
    /// peer with stable config produces *zero* SyncRoutes; a liveness rule
    /// based on "time since last SyncRoute" would delete every healthy peer.
    /// The desired set here is a pure function of the router and time never
    /// enters it.
    #[tokio::test(start_paused = true)]
    async fn desired_routes_survive_a_silent_peer() {
        let daemon = test_daemon(None).await;
        let nic_id: PeerId = 7;
        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(110, 20, 0, 9)),
            SAMPLE_NET,
        )
        .unwrap()
        .with_resource_version(1);
        assert!(daemon.apply_sync_route(peer.clone(), nic_id));

        let before = reconciler::desired(&[nic_id], &daemon.route_snapshot());
        assert_eq!(before.len(), 1);

        // Hours pass without a single SyncRoute for this peer.
        tokio::time::advance(std::time::Duration::from_secs(6 * 3600)).await;

        let after = reconciler::desired(&[nic_id], &daemon.route_snapshot());
        assert_eq!(before, after, "silence must not withdraw a route");

        // And the duplicate report the derper would have deduped anyway is a
        // no-op here as well.
        assert!(!daemon.apply_sync_route(peer, nic_id));
    }

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    async fn accepting_daemon(host_info: Option<HostInfo>) -> NoeioDaemon {
        let mut d = test_daemon(host_info).await;
        d.config.router.accept_routes = true;
        d
    }

    /// FR-2.5: a newer PeerInfo without a CIDR withdraws it — the desired
    /// set is recomputed from the full list, not patched incrementally.
    #[tokio::test]
    async fn newer_peer_info_withdraws_missing_subnets() {
        let daemon = accepting_daemon(None).await;
        let nic_id: PeerId = 7;
        let id = new_peer_id();
        let ip = IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1));
        let v1 = PeerInfo::new(id, ip, SAMPLE_NET)
            .unwrap()
            .with_resource_version(1)
            .with_advertised_routes(vec![cidr("192.168.10.0/24"), cidr("172.20.0.0/16")]);
        assert!(daemon.apply_sync_route(v1, nic_id));
        daemon.refresh_subnets();
        let want = reconciler::desired(&[nic_id], &daemon.route_snapshot());
        assert_eq!(want.len(), 3);
        assert!(
            daemon
                .router
                .lookup(&"172.20.1.1".parse().unwrap())
                .is_some()
        );

        let v2 = PeerInfo::new(id, ip, SAMPLE_NET)
            .unwrap()
            .with_resource_version(2)
            .with_advertised_routes(vec![cidr("192.168.10.0/24")]);
        assert!(daemon.apply_sync_route(v2, nic_id));
        daemon.refresh_subnets();
        let want = reconciler::desired(&[nic_id], &daemon.route_snapshot());
        assert_eq!(want.len(), 2);
        assert!(!want.iter().any(|k| k.cidr == cidr("172.20.0.0/16")));
        assert!(
            daemon
                .router
                .lookup(&"172.20.1.1".parse().unwrap())
                .is_none()
        );
        assert!(
            daemon
                .router
                .lookup(&"192.168.10.7".parse().unwrap())
                .is_some()
        );
    }

    /// FR-8.5 layer 2: a tombstone removes the peer and every route it
    /// contributed; a stale tombstone for an unknown peer is a no-op.
    #[tokio::test]
    async fn tombstone_removes_peer_and_its_subnets() {
        let daemon = accepting_daemon(None).await;
        let nic_id: PeerId = 7;
        let id = new_peer_id();
        let ip = IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1));
        let live = PeerInfo::new(id, ip, SAMPLE_NET)
            .unwrap()
            .with_resource_version(5)
            .with_advertised_routes(vec![cidr("10.0.0.0/8")]);
        assert!(daemon.apply_sync_route(live.clone(), nic_id));
        daemon.refresh_subnets();
        assert_eq!(
            reconciler::desired(&[nic_id], &daemon.route_snapshot()).len(),
            2
        );

        let tombstone = live.clone().with_withdrawn(true);
        assert!(daemon.apply_sync_route(tombstone.clone(), nic_id));
        daemon.refresh_subnets();
        assert!(reconciler::desired(&[nic_id], &daemon.route_snapshot()).is_empty());
        assert!(daemon.router.get_by_peer_id(&id).is_none());
        assert!(!daemon.apply_sync_route(tombstone, nic_id));

        // The peer coming back is a fresh insert, not a stale-version skip.
        assert!(daemon.apply_sync_route(live.with_resource_version(1), nic_id));
    }

    /// accept_routes = false (C-2 / AC-12): advertisements are learned but
    /// nothing is installed and lookup never resolves through them.
    #[tokio::test]
    async fn accept_routes_off_installs_no_subnets() {
        let daemon = test_daemon(None).await;
        let nic_id: PeerId = 7;
        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap()
        .with_resource_version(1)
        .with_advertised_routes(vec![cidr("10.0.0.0/8")]);
        assert!(daemon.apply_sync_route(peer, nic_id));
        daemon.refresh_subnets();
        let want = reconciler::desired(&[nic_id], &daemon.route_snapshot());
        assert_eq!(want.len(), 1, "only the /32 host route");
        assert!(daemon.router.lookup(&"10.1.2.3".parse().unwrap()).is_none());
        let decisions = daemon.decisions.read().unwrap().clone();
        assert_eq!(decisions[0].rejected, Some(routes::Rejection::PolicyOff));
    }

    /// FR-1.6: changing what we advertise bumps HostInfo.resource_version and
    /// updates every local PeerInfo, or the derper would dedupe the report.
    #[tokio::test]
    async fn set_advertised_bumps_version_and_updates_peers() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;
        daemon
            .add_peer(
                PeerInfo::new(
                    new_peer_id(),
                    IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1)),
                    SAMPLE_NET,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let before = daemon
            .host_info
            .lock()
            .await
            .as_ref()
            .unwrap()
            .resource_version;

        daemon.set_advertised(vec![cidr("192.168.10.0/24")]).await;
        let host = daemon.host_info.lock().await.clone().unwrap();
        assert!(host.resource_version > before);
        assert_eq!(
            host.peers[0].advertised_routes,
            vec![cidr("192.168.10.0/24")]
        );

        // Unchanged set: no bump.
        daemon.set_advertised(vec![cidr("192.168.10.0/24")]).await;
        assert_eq!(
            daemon
                .host_info
                .lock()
                .await
                .as_ref()
                .unwrap()
                .resource_version,
            host.resource_version
        );
    }

    /// AC-16 (3): what a node advertises is exactly what passed the gate; a
    /// consumer-only platform therefore never puts a CIDR into PeerInfo.
    #[tokio::test]
    async fn advertised_routes_only_enter_peer_info_through_the_gate() {
        let mut cfg = Config::default();
        cfg.router.advertise_routes = vec!["192.168.10.0/24".to_string()];
        let accepted = cfg.validate_routes(&routes::Protected::default());
        let advertised: Vec<Ipv4Cidr> = accepted.unwrap_or_default();
        if routes::platform_can_advertise() {
            assert_eq!(advertised, vec![cidr("192.168.10.0/24")]);
        } else {
            assert!(advertised.is_empty());
        }
        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(110, 20, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap()
        .with_advertised_routes(advertised.clone());
        assert_eq!(peer.advertised_routes, advertised);
    }

    #[tokio::test]
    async fn add_peer_returns_err_when_host_info_is_none() {
        let daemon = test_daemon(None).await;
        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        assert!(daemon.add_peer(peer).await.is_err());
    }

    #[tokio::test]
    async fn add_peer_pushes_new_peer() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let peer = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        let peer_clone = peer.clone();
        daemon.add_peer(peer).await.unwrap();

        let info = daemon.host_info.lock().await;
        let peers = &info.as_ref().unwrap().peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].noeio_ip, peer_clone.noeio_ip);
        assert_eq!(peers[0].peer_id, peer_clone.peer_id);
    }

    #[tokio::test]
    async fn add_peer_updates_existing_peer_id_by_ip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let old_id = new_peer_id();
        let new_id = new_peer_id();

        daemon
            .add_peer(PeerInfo::new(old_id, ip, SAMPLE_NET).unwrap())
            .await
            .unwrap();
        daemon
            .add_peer(PeerInfo::new(new_id, ip, SAMPLE_NET).unwrap())
            .await
            .unwrap();

        let info = daemon.host_info.lock().await;
        let peers = &info.as_ref().unwrap().peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, new_id);
    }

    #[tokio::test]
    async fn add_peer_different_ips_both_kept() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820);
        let daemon = test_daemon(Some(HostInfo::new(addr))).await;

        let p1 = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            SAMPLE_NET,
        )
        .unwrap();
        let p2 = PeerInfo::new(
            new_peer_id(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            SAMPLE_NET,
        )
        .unwrap();
        daemon.add_peer(p1).await.unwrap();
        daemon.add_peer(p2).await.unwrap();

        let info = daemon.host_info.lock().await;
        assert_eq!(info.as_ref().unwrap().peers.len(), 2);
    }
}
