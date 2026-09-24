# Subnet router requirements

Status: Draft
Date: 2026-09-22
Related code: `noeio`, `noeio-common`, `noeio-derp`, `noeio-proto`, `noeio-net-route`

> Chinese original: [docs/subnet-router-requirements.md](../subnet-router-requirements.md). Keep both in sync when editing.

---

## 1. Background

noeio today is a pure host overlay. Every node requests a virtual IP when it joins the network (`PeerInfo.noeio_ip`), the `Router` table hashes on that virtual IP as an exact key (`noeio/src/daemon/router.rs:19`), and the system side installs only `/32` routes (`noeio/src/daemon/nic.rs:28`). Traffic can therefore only flow between machines that run noeio.

Plenty of real resources cannot run an agent: physical servers in a datacenter, NAS boxes, printers, an RDS instance inside a cloud VPC, a Kubernetes pod network, cameras on an office LAN. Reaching them requires a node already in the overlay to act as a subnet router and proxy traffic for a whole prefix.

This document specifies that capability. The semantics line up with Tailscale's `--advertise-routes` / `--accept-routes` and WireGuard's `AllowedIPs`.

## 2. Goals and non-goals

### 2.1 Goals

- Node A can declare locally a set of CIDRs it is willing to proxy (the subnet router role).
- That set syncs to the other nodes in the same network over the existing derper broadcast path.
- On receipt, each node installs system rules so that outbound packets whose destination falls in one of those CIDRs enter the noeio virtual interface.
- noeio maintains a CIDR to peer to session mapping internally and sends the packet to node A over the best available link.
- Node A SNATs the packet, forwards it into the real subnet, and keeps the NAT session so replies can be DNATed back to the original overlay source.

### 2.2 Non-goals (out of scope this cycle)

- The Advertiser role on non-Linux platforms. macOS and Windows nodes can only be Consumers this cycle; advertise requests are rejected with a warning per FR-9. The design sketch for macOS pf survives in FR-5.4 and is listed as a later feature.
- IPv6 subnet routes. `noeio-net-route` and the `smoltcp` configuration are both IPv4 only right now (`noeio-net-route/src/lib.rs:51`, workspace `smoltcp` features = `proto-ipv4`).
- Exit nodes (a full `0.0.0.0/0` egress). The protocol allows it, but advertising it is rejected by default. See FR-1.5.
- Load balancing across several advertisers of the same CIDR. This cycle picks a single active advertiser with standbys. See FR-3.4.
- ACLs or identity-based access control. Any node in the network can use an accepted subnet route.
- Subnet hosts initiating traffic toward overlay nodes. Only the overlay to subnet direction is supported; replies rely on the NAT session.

## 3. Terminology

| Term | Meaning |
| --- | --- |
| Subnet router / Advertiser | The noeio node that advertises and proxies a CIDR |
| Consumer | The noeio node that accepts that CIDR and steers traffic into the overlay |
| Advertised route | A CIDR the Advertiser declares it can proxy |
| Accepted route | A CIDR the Consumer actually installs into its local system |
| LAN-side interface | The physical NIC on the Advertiser facing the real subnet |
| NAT session | The bidirectional mapping `(proto, overlay_src_ip, overlay_src_port, dst_ip, dst_port)` to `(lan_src_ip, lan_src_port)` |

## 4. Scenario

```
   Host-B (no agent)                Host-C
   192.168.10.7                     a machine inside 10.0.0.0/8
        |                                |
   [ office LAN 192.168.10.0/24 ]   [ VPC 10.0.0.0/8 ]
        |                                |
   +----+----------------+          +----+----------------+
   | Noeio A             |          | Noeio D             |
   | vip 110.20.0.1      |          | vip 110.20.0.9      |
   | advertise           |          | advertise           |
   |   192.168.10.0/24   |          |   10.0.0.0/8        |
   +----+----------------+          +----+----------------+
        |         overlay (WireGuard over UDP, direct or relayed via derper)
        +--------------------+-------------------+
                             |
                    +--------+--------+
                    | Noeio E         |
                    | vip 110.20.0.5  |
                    | accept routes   |
                    +-----------------+

`curl http://192.168.10.7` on Noeio E should just work.
```

## 5. Functional requirements

### FR-1 Local CIDR configuration (Advertiser side)

- **FR-1.1** Advertised routes can be declared in the config file. The new section lands in `noeio/src/config.rs`, where `Config` currently has only `stun` and `derper` (`config.rs:4`); the empty `pub struct Noeio {}` placeholder can be reused:

  ```toml
  [router]
  # subnets this node proxies, as a CIDR list
  advertise_routes = ["192.168.10.0/24", "172.20.0.0/16"]
  # whether to accept subnet routes advertised by other nodes
  accept_routes = true
  # whether to configure forwarding and SNAT automatically when acting as a subnet router
  auto_nat = true
  # LAN-side egress interface; empty means pick it by looking up the system route for the destination
  lan_interface = ""
  ```

- **FR-1.2** The CLI can override or append, in the style of the existing `--stun` / `--derper` flags (`noeio/src/cli.rs:15`, `value_delimiter = ','`): `noeio boot --advertise-routes 192.168.10.0/24 --accept-routes`. The merge logic follows `append_stuns` / `append_derpers` in `config.rs`.
- **FR-1.3** Routes can be added and removed at runtime over RPC without restarting the process. See FR-7.
- **FR-1.4** CIDRs must be validated: parseable, network address consistent with the prefix length (`192.168.10.1/24` normalizes to `192.168.10.0/24` with a warning), prefix length within `[8, 32]`.
- **FR-1.5** Reject the following advertisements with a clear error:
  - `0.0.0.0/0` and any route with a prefix length below 8 (exit node, unsupported this cycle);
  - any CIDR that contains the overlay's own prefix (it would loop overlay traffic back on itself);
  - any CIDR that contains a derper address or the current STUN server address, which is the easiest way to cut the control plane and strand the node;
  - `127.0.0.0/8` and `169.254.0.0/16`.
- **FR-1.6** A change to the advertised routes must increment `HostInfo.resource_version`. The derper's `PeerManager::heartbeat` deduplicates reports by monotonic `resource_version` comparison (`noeio-derp/src/connection/peer.rs`), so without the bump the whole report is discarded as a duplicate and no broadcast happens. The field is currently refreshed only when a STUN response arrives (`noeio/src/daemon.rs:557`); this cycle needs an explicit bump on the route-change path.

### FR-2 Route propagation (control plane)

- **FR-2.1** `PeerInfo` gains a field for advertised routes:
  - proto: `message PeerInfo` in `noeio-proto/protos/common/v1/host_info.proto` gains `repeated string advertised_routes = 8;`. Field numbers 1 through 7 are taken and must not be reused.
  - Rust: `PeerInfo` at `noeio-common/src/host_info.rs:72` gains `pub advertised_routes: Vec<IpCidr>` plus a `with_advertised_routes` constructor.
  - Both conversions, `From<&PeerInfo> for ProtoPeerInfo` and `TryFrom<ProtoPeerInfo>`, change alongside.
- **FR-2.2** Compatibility: a `PeerInfo` reported by an older node has no such field and parses as an empty list (`unwrap_or_default`); an older node receiving the field ignores it as an unknown field per protobuf semantics and must not fail to parse. The legacy text format in `host_info.rs` (comma and `\r\n` separated) does not gain the field; it only has to keep parsing.
- **FR-2.3** Report path: advertised routes ride the periodic `HostInfo` `Report` packet to the derper, once every 10 seconds (`noeio/src/daemon.rs:260`, `register_host_info`), in the same place as the existing `local_addrs` refresh.
- **FR-2.4** Broadcast path: the derper's `handle_sync` (`noeio-derp/src/connection.rs`) already pushes a `SyncRoute` packet to every node in the network, with `PeerInfo` protobuf as the payload, so the new field is broadcast automatically and the derper needs no new message type. The derper does not validate CIDR semantics; it passes them through.
- **FR-2.5** Withdrawal has to propagate. The protocol today has incremental addition only, with no delete semantics: the node-side `Router` never removes a peer, and on the derper side a peer expires only by silent moka TTL after one minute. Withdrawal is therefore expressed as "the CIDR is absent from a newer `PeerInfo`", which means the Consumer must do a full diff, replacing the old list with the new one and withdrawing the difference, rather than processing additions only. This capability has to be built this cycle.
- **FR-2.6** Observability: the `SyncRoute` handling path needs one `tracing` line each for route addition, withdrawal, and conflict rejection, carrying `peer_id`, `cidr`, and `resource_version`.

### FR-3 System rule installation (Consumer side)

- **FR-3.1** When a Consumer receives a `SyncRoute` carrying `advertised_routes` (`noeio/src/daemon.rs:430`, which currently installs only a `/32` for `peer.noeio_ip`), it installs a forwarding rule per accepted CIDR so that outbound packets destined for that CIDR enter the noeio virtual interface.
- **FR-3.2** The preferred mechanism is the system routing table, not iptables, for three reasons:
  - `add_route(target, netmask, ifindex, metric)` in `noeio-net-route` already handles any contiguous netmask (`netmask_to_prefix`, `noeio-net-route/src/lib.rs:50`), with Linux and Windows on the `net-route` crate and macOS on the in-house `PF_ROUTE` path, so all three platforms are covered;
  - `VirtualNic::add_router_rule` already takes a netmask string (`noeio/src/interface/virtual_nic.rs:42`); only its caller `NicManager::route` hardcodes `"255.255.255.255"`;
  - routing tables exist on all three platforms while iptables exists only on Linux, so steering traffic with iptables would mean a second implementation for macOS and Windows and twice the maintenance.

  `NicManager::route` therefore needs to accept a prefix length (or gain a `route_cidr`) so the hardcoded `/32` becomes a parameter.
- **FR-3.3** netfilter rules are confined to policy routing and NAT on Linux, that is FR-5, plus one optional case: when a user wants only traffic from specific sources or carrying a specific mark to use the subnet route, a meta mark combined with policy routing rules. This is an optional enhancement, off by default; once enabled, those rules also go over netlink (FR-5.8) and live in the dedicated table.
- **FR-3.4** Route conflict handling, highest priority first:
  1. A CIDR that conflicts with a directly connected prefix on a local physical interface: refuse to install, log WARN. The local LAN wins. This is a hard rule, since otherwise the user's own network breaks.
  2. A CIDR that conflicts with one this node advertises itself: refuse to install, because this node is the egress. An Advertiser never installs a route toward the TUN for a CIDR it advertises. It sits inside that prefix physically and already has a directly connected route over the physical NIC; a second route would loop. §8.1.1 covers how the cleanup duties differ by role.
  3. Several peers advertising the same CIDR: pick the lowest `peer_id` as the active egress, which is deterministic and needs no negotiation, and record the rest as standby. When the active peer's `PeerInfo` disappears from the derper (TTL expiry) or its link stays unusable for a long time, fail over to the next standby.
  4. Peers advertising CIDRs that contain one another, say `10.0.0.0/8` and `10.1.0.0/16`: install both and let longest-prefix match sort it out.
- **FR-3.5** Routes must be withdrawable, and withdrawal must be state convergence rather than imperative deletion. See §FR-8.

### FR-4 Internal CIDR to link mapping (outbound data plane)

- **FR-4.1** `Router` (`noeio/src/daemon/router.rs:17`) gains a prefix table alongside the existing exact table:

  ```
  peers:      DashMap<IpAddr, Arc<Peer>>      // existing, /32 host routes
  by_peer_id: DashMap<PeerId, IpAddr>         // existing
  subnets:    RwLock<Vec<(IpCidr, PeerId)>>   // new, sorted by descending prefix length
  ```

- **FR-4.2** Add `lookup(&self, ip: &IpAddr) -> Option<Arc<Peer>>`: check `peers` for an exact match first, since host routes always win, then fall back to longest-prefix match over `subnets` and resolve the hit to an `Arc<Peer>` through `by_peer_id`.
- **FR-4.3** `process_outbound` (`noeio/src/daemon.rs:187`) switches `router.get(&dst_ip)` to `router.lookup(&dst_ip)`. A miss currently means `tracing::error!` plus `continue` and a dropped packet (`daemon.rs:188`); after the change the miss log drops to `debug`, since with subnet routing a miss is routine rather than an error.
- **FR-4.4** Link selection reuses the existing machinery and adds no new logic. `Peer::select_session` already picks the lowest RTT with 20% hysteresis (`noeio/src/daemon/peer.rs:259`), and `send_to_peer` already falls back from direct to derper relay (`noeio/src/daemon.rs:124`). Subnet routing only maps more destination IPs onto the same `Peer`; the link layer never notices.
- **FR-4.5** Lookup performance: `lookup` sits on the hot path of every outbound packet. This cycle may implement it as a linear scan over a `Vec` sorted by descending prefix length, since the advertised-route count is expected to stay under 100 and reads vastly outnumber writes, but it must use an `RwLock` read lock or `ArcSwap` so a write never blocks forwarding. Switch to an LPM trie if the scale grows later. Include a benchmark, or at minimum a comment recording the tradeoff.
- **FR-4.6** Dependencies: prefer `smoltcp::wire::Ipv4Cidr` for the CIDR type, since it is already in the dependency tree with `proto-ipv4` enabled, to avoid pulling in `ipnet`. If the `Ipv4Cidr` API falls short, for instance lacking string parsing, introduce `ipnet` and explain why in the PR description.

### FR-5 SNAT and forwarding (Advertiser side, inbound data plane)

- **FR-5.1 Relax the anti-spoofing check (blocking prerequisite).** `handle_delivery` currently requires the decrypted inner source IP to equal that peer's virtual IP and drops the packet otherwise (`noeio/src/daemon.rs:593-602`). A subnet route's reply carries the subnet host's address, or its post-NAT LAN address, so this line drops it outright. The check changes to WireGuard `AllowedIPs` semantics: pass when the inner source IP is in `{peer.noeio_ip} ∪ peer.advertised_routes`.

  > This is the key prerequisite for the whole feature. Without it, subnet routing fails on any implementation path. It is also the security boundary: the relaxation stays strictly inside the CIDRs that peer has advertised, and the check cannot simply be dropped.

- **FR-5.2** Symmetrically, the outbound direction needs an AllowedIPs constraint too: a packet must not go to a peer that has not advertised its destination prefix. FR-4.2's table structure guarantees this naturally, but it needs test coverage.
- **FR-5.3 SNAT implementation path.** The recommended approach is kernel assistance (M2), with userspace NAT as the fallback (see §9, open question Q1):

  **Kernel-assisted (Linux, recommended)** requires this kernel state:
  1. Forwarding enabled: `net.ipv4.ip_forward=1`. Record the original value and restore it on exit (FR-8.8).
  2. SNAT: masquerade at postrouting for packets whose source is in the overlay prefix and whose output interface is the LAN NIC.
  3. Forward acceptance: allow TUN to LAN, plus the reverse direction gated on conntrack state (`established,related`).
  4. Reply DNAT happens automatically in kernel conntrack, so noeio keeps no NAT table. Conntrack restores the destination to the overlay source IP, the kernel sends it into the TUN via the overlay `/32` route that already exists, and noeio reads it from `process_outbound` and encrypts it back as usual.

  This path hands the job of maintaining SNAT rules and the later reply DNAT to conntrack. noeio maintains three rules instead of per-session state, which is substantially less code and less surface for mistakes.

  **See FR-5.8 for how the rules get installed. The `iptables` and `nft` command lines are not used.**

- **FR-5.8 netfilter rule installation: netlink, no command-line binaries.**

  `noeio-net-route/src/lib.rs:3` already established the architectural convention for this project:

  > *"so callers stay independent of platform-specific interface-name APIs and **no `route`, `ip`, or `netsh` binary is needed at runtime**"*

  NAT rules follow the same convention. The reason goes beyond consistency: this is a measured constraint. The build image used for the §12 verification has **neither `ip` nor `iptables`**, only `sysctl`. Slim images, distroless containers, and modern distributions shipping nftables without an iptables compatibility layer all turn "shell out to iptables" into a failure that only surfaces at deployment.

  - **FR-5.8.1** Configuring rules by invoking `iptables`, `ip6tables`, or `nft` through `std::process::Command` is **forbidden**. That also rules out the `iptables` crate on crates.io, which wraps the iptables binary in `std::process::Command`, and the `nftables` crate, which is JSON over `nft -j -f -`. Both names mislead; both are command-line wrappers.
  - **FR-5.8.2** **Selected approach: a new module inside `noeio-net-route` built on `netlink-packet-netfilter` `=0.4.0` (MIT).** It implements only the narrow path this cycle needs: create a table, create a base chain, add rules, encode masquerade / ct state / interface-match expressions, and delete the whole table. It is not a general nftables wrapper.

    The crate **ships an `nftables` module** already, with attribute enums, message types, and the nfgenmsg header, so the effort is lower than expected: roughly **200 to 350 lines** instead of coding from scratch. The only gaps are the masq, ct, and counter expressions, filled in by hand-encoding through `Expressions::Other` plus `DefaultNla`, with no fork required.

    **A separate document covers the details: [nf_tables netlink layer requirements](../nftables-netlink-requirements.en.md)**, with API shape, transaction semantics, expression encoding, environment detection, seven acceptance criteria, and a step-by-step implementation path.
  - **FR-5.8.3** **`rustables` is unusable because of a license conflict.** It is the only mature pure-Rust netlink option (0.9.0, no C library linkage, complete NAT support), but it is **GPL-3.0-or-later** while this project is **Apache-2.0** (see the repository `LICENSE`). GPL-3.0's copyleft would require releasing the whole work under GPL-3.0, which is incompatible. **Record this conclusion in a code comment** so nobody pulls it in casually later.
  - **FR-5.8.4** `nftnl` / `nftnl-sys` (Mullvad) is out for the same reason: it is an FFI binding to `libnftnl` plus `libmnl`, dynamically linked through `pkg-config` with **no vendored feature**, meaning a C library per target architecture when cross-compiling. The project has `build/cross` cross-compilation images, and that cost is unacceptable.

  **Table naming and priority, so the user's existing configuration survives:**

  - **FR-5.8.5** **Do not use `nat`, `filter`, or `mangle` as table names.** `iptables` on modern distributions is usually iptables-nft, which creates tables by those names and keeps the fixed legacy priorities; the nftables project explicitly advises against editing them directly. noeio creates its own table named `noeio` in the `ipv4` (or `inet`) family, containing its own base chains. Ownership is then clear, the table can be deleted atomically, and user rules are untouched. This matches the intent of FR-8.8's "own chain", expressed in the nftables table and chain model.
  - **FR-5.8.6** Set base chain hook priorities explicitly: `100` for srcnat, matching legacy `nat(src)`, and `0` for forward filtering. **Ordering among equal priorities is undefined**, since it depends on module load and creation order, and must not be relied on.
  - **FR-5.8.7** Commit the ruleset in a `Batch`-style atomic transaction so traffic never forwards through a half-configured state.

  **Known coexistence behavior with existing iptables rules** (needed for troubleshooting, no code required):

  - **FR-5.8.8** nftables and iptables-legacy do not override one another. They share the same Netfilter hooks, conntrack, and NAT engine, and are traversed in ascending hook priority.
  - **FR-5.8.9** But **NAT is stateful**: once conntrack has bound a NAT translation to a flow in one direction, that flow is not translated a second time. So if a pre-existing iptables-legacy MASQUERADE rule matches first, noeio's masquerade silently becomes a no-op, and vice versa. This failure mode is subtler than a filter chain verdict and **must go into the troubleshooting doc**.
  - **FR-5.8.10** The genuinely dangerous environment is iptables-legacy and iptables-nft **in use at the same time**, because each userspace tool sees only its own half of the rules. Log the detection result at startup, a summary of the current ruleset, to make after-the-fact troubleshooting possible.

  **Runtime environment requirements:**

  - **FR-5.8.11** Minimum kernel **4.18**. Before 4.18 both the prerouting and postrouting NAT chains had to be registered or reply packets were not NATed, since registering the chain is what attaches the NAT engine to the hook. If the masquerade rule needs to match on the **inbound interface**, the minimum rises to **5.5**, when the POSTROUTING hook gained the ability to match `iifname`.
  - **FR-5.8.12** Required kernel config: `NF_TABLES`, `NF_TABLES_IPV4`, `NF_TABLES_NAT`, `NFT_MASQ`, `NFT_CT`, plus `NF_CONNTRACK` and `NF_NAT` underneath. Detect what is missing at startup and produce an error that **names the missing item** rather than a generic "configuration failed".
  - **FR-5.8.13** Inside a container this needs `CAP_NET_ADMIN` **and a separate network namespace**, because when the host netns is shared the permission check lands on `init_net` and an unprivileged userns cannot get it. `--privileged` is not required. Note that **even a read-only rule listing needs CAP_NET_ADMIN**, since modern kernels gate `nf_tables_getgen` too.
  - **FR-5.8.14** The most common container failure is `nft_masq`, `nft_nat`, `nf_nat`, or conntrack **not autoloading from an unprivileged userns**, which shows up as `No such file or directory` when adding the NAT chain. Document modprobing them on the host as a prerequisite, and give a pointed hint when that errno appears.

  **Userspace NAT (fallback, and for non-Linux platforms)**
  - noeio maintains its own NAT session table: key `(proto, overlay_src, src_port, dst, dst_port)` to `(lan_src_ip, allocated_port)`, with port pool allocation and separate aging for TCP, UDP, and ICMP (TCP established keyed on FIN/RST plus a timeout, UDP a fixed timeout, ICMP mapped by id).
  - It needs `smoltcp`'s `Ipv4Packet` / `TcpPacket` / `UdpPacket` to rewrite addresses and ports and **recompute the IP and L4 checksums**. A pseudo-header change affects both the TCP and UDP checksum, and the original header embedded in an ICMP error has to be rewritten too.
  - It also needs to inject packets into the physical network through a raw socket, which differs substantially across the three platforms.
  - This approach is far more complex than the kernel one and is used only when the kernel path is unavailable.

- **FR-5.4** (deferred) The macOS Advertiser pf path: `sysctl net.inet.ip.forwarding=1` plus a pfctl `nat on <lan_if> from <overlay_cidr> to any -> (<lan_if>)`, with the rules in their own anchor such as `noeio`. **Not implemented this cycle**, see FR-5.5; the sketch stays here as a reference for the later feature.
- **FR-5.5 The Advertiser is Linux-only.** macOS and Windows nodes **can only be Consumers** and must not act as subnet routers. SNAT, IP forwarding, and MSS clamp either need a separate implementation off Linux (macOS pf) or do not exist (Windows), and a half-finished Advertiser in production fails as "an entire prefix is a black hole for the whole network", which costs far more than not supporting it. The macOS pf path (formerly FR-5.4) moves out of this cycle's scope and becomes a later feature. §FR-9 covers the rejection semantics.
- **FR-5.6** Privileges: configuring `ip_forward`, iptables, or pf all need root or Administrator. The noeio daemon already needs privileges to create the TUN, so this adds no new requirement, but when privileges are insufficient it must produce an **actionable error** rather than silently degrading.
- **FR-5.7 MTU and fragmentation.** The noeio TUN MTU is 1411 (`noeio/src/interface/virtual_nic.rs:13`). A 1500-byte packet from a subnet host, forwarded into the overlay by the Advertiser, needs fragmentation or triggers PMTUD, and PMTUD breaks on many networks where ICMP is filtered. The classic symptom is "ping works but a large HTTP response hangs". Required:
  - MSS clamp on forwarded TCP SYNs on Linux (the equivalent of nftables' `tcp option maxseg size set rt mtu`), installed over netlink per FR-5.8, with the rule in the dedicated `noeio` table;
  - for large non-TCP packets, allow fragmentation when DF is unset, or return `ICMP Fragmentation Needed` correctly;
  - document the limitation.

### FR-6 Reply path (DNAT)

- **FR-6.1** Under the kernel-assisted approach the reply path is: subnet host, Advertiser LAN NIC, conntrack reverse NAT restoring the destination to the overlay source IP, kernel route lookup hitting the overlay `/32`, write into the TUN, noeio `process_outbound` reads it, `Router::lookup` resolves the overlay peer, encrypt and send back. **This path falls out of FR-4 and FR-5.1 with no extra code.**
- **FR-6.2** The userspace approach needs a reverse lookup: an inbound physical packet is matched by `(proto, dst_ip=lan_src_ip, dst_port=allocated_port)` against the NAT session, the original overlay source is restored, and the packet is encrypted and sent back.
- **FR-6.3** NAT session (or conntrack table) capacity and aging need to be observable: expose active session count, port pool utilization, and aging eviction counts.
- **FR-6.4** The route to the overlay source address must exist on the Advertiser. The Consumer's `/32` is already installed by the existing `SyncRoute` flow (`noeio/src/daemon.rs:480`), but confirm it is also installed when the Advertiser has not yet built a tunnel to that Consumer; otherwise the kernel drops the first reply for want of a route.

### FR-7 Control plane interface (RPC and CLI)

- **FR-7.1** Add the proto file `noeio-proto/protos/noeio/v1/route.proto` (`noeio-proto/build.rs` collects by directory, so no filename registration is needed):

  ```
  service RouteService {
    rpc AdvertiseRoute(AdvertiseRouteRequest) returns (AdvertiseRouteResponse);
    rpc WithdrawRoute(WithdrawRouteRequest) returns (WithdrawRouteResponse);
    rpc ListRoutes(ListRoutesRequest) returns (ListRoutesResponse);
  }
  ```

  `RouteEntry` carries at least `cidr`, `peer_id`, `via` (the remote virtual IP), `source` (local or remote), `state` (active, standby, or rejected), and `reject_reason`.
- **FR-7.2** The server implementation goes in `noeio/src/rpc/service/route.rs`, registered with `.add_service(...)` inside `run` at `noeio/src/rpc/service.rs:13`, matching the existing `DaemonService` and `VirtualNicService`.
- **FR-7.3** CLI: add `noeio route advertise <cidr>`, `noeio route withdraw <cidr>`, and `noeio route list`. On the client side, `CliRpcClient` at `noeio/src/rpc/client.rs:8` gains a `route_client` field and `noeio/src/main.rs` gains the dispatch.
- **FR-7.4** The `route list` output has to answer the three questions people actually ask while troubleshooting: which peer this CIDR was learned from, which link it currently takes (direct or relayed), and why it is not in effect.
- **FR-7.5** The RPC channel today is a Unix socket at `/var/run/noeio.sock`, or a Windows named pipe (`noeio/src/rpc.rs:5`), with **no authentication**, relying on file permissions alone. Subnet routing is a privileged operation that rewrites system routes and NAT, so this cycle must at least confirm the socket is mode `0600` owned by root, and record the trust model in the docs.

### FR-8 Zombie rule management (blocking)

This is the highest-risk part of the feature, so it gets its own section.

#### 8.0 Current state (verified)

| Fact | Location |
| --- | --- |
| The `noeio` daemon has **no exit signal handling at all** | `noeio/src/main.rs:37`: `service::run(state).await` runs until killed. `noeio-derp/src/main.rs:158` does handle SIGTERM and ctrl_c; the daemon side does not |
| The whole workspace has **no `impl Drop`** | grep across the repository returns nothing |
| `Router::remove` **is defined but never called** | `noeio/src/daemon/router.rs:74`, no callers |
| `NicManager::remove` **is defined but never called** | `noeio/src/daemon/nic.rs:51`, the only reference is its own implementation |
| There is no `del_route` | `noeio-net-route/src/lib.rs` has only `add_route` |
| Route installation is imperative | `noeio/src/daemon.rs:480` calls `nics.route(...)` directly with no corresponding withdrawal path |

The cleanup path is not incomplete; none of it exists, and there is currently no exit flow to hook into. The defect is already present for `/32` host routes, where the consequence is one unreachable overlay IP. Subnet routing scales it up to an entire prefix going dark.

#### 8.1 Splitting the problem

The two problems differ **fundamentally in how solvable they are**, so they need separate designs:

- **P1: withdrawal does not take effect while the process lives.** Purely in-process state, and fully solvable.
- **P2: rules linger after abnormal exit.** Under SIGKILL, panic, or power loss, neither `Drop` nor signal handlers run, so no in-process mechanism can cover it. The only options are convergence at startup or letting the rules die with the process naturally.

#### 8.1.1 Cleanup duties by role

Combined with the §12 verification results, the burden of the two problems falls very unevenly across roles. **This is the main basis for trimming implementation scope.**

| | Subnet CIDR routes | Overlay `/32` routes | sysctl | iptables / pf |
| --- | --- | --- | --- | --- |
| **Consumer** (accepts routes) | installs (toward TUN) | installs (toward TUN) | — | — |
| **Advertiser** (advertises plus SNAT) | **does not install** | installs (toward TUN) | modifies | modifies |

- **An Advertiser installs no route for the CIDRs it advertises.** It is physically inside that prefix and already has a directly connected route over the physical NIC; a second route toward the TUN would loop. The first two conflict rules in FR-3.4 exist to forbid exactly this.
- So **"delete the subnet route" is a Consumer-side P1 item, not an Advertiser one**.
- The Advertiser still maintains `/32` routes to each Consumer's overlay IP, which FR-6.4 requires so replies are not dropped for want of a route. But that is identical for every node and goes through the same reconciler, so it is not an Advertiser-specific burden.

The real scope per role follows:

| Role | Platform | P1 | P2 |
| --- | --- | --- | --- |
| Consumer only | all three | needed (delete subnet routes plus `/32`) | **mostly unnecessary**, since every route it installs has the TUN as output interface, and the kernel already reclaims those (§12 experiments 1 and 3) |
| Advertiser | **Linux only** (FR-5.5 / FR-9) | needed (delete `/32`) | **needed**, because sysctl and iptables are confirmed to linger (§12 experiment 4) |

Because the Advertiser is Linux-only, the P2 implementation **only has to cover Linux**, and the §12 conclusions happen to cover that single target platform completely. The unverified TUN reclamation behavior on macOS and Windows (the FR-8.7 leftover) no longer blocks this cycle: those platforms are Consumers only, and a Consumer touches nothing but the routing table on any platform.

**Roles are hats, not node attributes.** One node can advertise `192.168.10.0/24` while accepting someone else's `10.0.0.0/8`, in which case both hats' duties apply. The implementation therefore **must not branch on "is this node an Advertiser or a Consumer"** but on "for this CIDR, is this node the advertiser or the user", which FR-8.2's pure function `desired = f(Router)` expresses naturally.

The Linux Advertiser's P2 implementation is small: **delete and recreate the dedicated `noeio` table at startup, and restore the original sysctl values from a file.** See FR-8.8 and FR-8.9.

Two things not to misread:

- **`del_route` is still required despite the verification results.** It is the prerequisite for P1, since a withdraw while the process lives has to actually delete the route, so FR-8.11 keeps its status as an M0 blocker. §12 removed the P2 mechanics, not the P1 ones.
- **FR-3.3's optional mangle / MARK policy routing, once enabled, produces residue on Consumers too**, since those rules do not hang off the TUN. It is off by default; enabling it requires bringing in the own-chain mechanism as well.

#### 8.2 P1 approach: reconciler (state convergence)

- **FR-8.1** Installing system rules imperatively on the `SyncRoute` handling path is forbidden. The existing `nics.route(...)` call at `noeio/src/daemon.rs:480` gets refactored along with it. A shape with add but no delete inevitably produces zombies; adding a `del_route` and then "remembering to call it" is the same trap a second time.
- **FR-8.2** Introduce a single source of truth and a convergence loop:

  ```
  desired   := f(Router state)      // pure function: peers × advertised_routes × accept policy
  installed := the rule set actually pushed to the kernel (persisted, see FR-8.7)
  reconcile(): diff(desired, installed) → apply the difference (adds and deletes)
  ```

  `SyncRoute` only updates in-memory `Router` state and calls `notify`; the reconciler wakes on that notify or on a periodic tick.
- **FR-8.3** `/32` host routes and subnet CIDR routes **must go through the same reconciler**. Otherwise two code paths coexist and the existing `/32` zombie defect survives.
- **FR-8.4** Reconcile is idempotent, so it also heals drift caused by an administrator running `ip route del` by hand or by third-party tooling.
- **FR-8.5 Three layers of withdrawal signal.** The layers have different jobs, and dropping any one of them leaves a scenario uncovered:

  1. **Explicit withdrawal (main path)**: the CIDR is absent from a newer `PeerInfo`, so the full diff deletes it. Covers `route withdraw` and config changes.
  2. **Peer disappearance (a protocol gap, needs derper changes)**: the derper's moka cache supports an eviction listener, so when an entry's TTL expires it actively pushes a tombstone to the other nodes in the network. Either `SyncRoute` gains a `withdrawn` flag or a new `PeerGone` packet type appears. Covers a remote crash, network loss, or power loss. **Layer 1 cannot handle these**, because sending a withdrawal presumes the remote is still alive.
  3. **Backstop**: periodic reconcile. On the Consumer side the existing `Peer` session state and RTT information (`noeio/src/daemon/peer.rs:259`) can tell whether a link has been unusable for a long time.

- **FR-8.6 Never judge peer liveness by "how long since the last `SyncRoute`".** The derper's `PeerManager::heartbeat` deduplicates by monotonic `resource_version` (`noeio-derp/src/connection/peer.rs:38`), so **a healthy peer with a stable configuration produces zero `SyncRoute` packets**. Using packet arrival time as a liveness signal would delete the routes for every healthy peer. This is the easiest serious bug to write in this feature, and a test must guard it.

#### 8.3 P2 approach: convergence at startup

- **FR-8.7 Route side: verified on Linux.** The assumption that "a route whose output interface is the TUN is reclaimed by the kernel when the TUN disappears" **holds**. §12 has the procedure and the data.

  Key points:
  - The device noeio creates through the `tun` crate has `tun_flags = 0x1001`, with `IFF_PERSIST` (0x0800) clear, so it is **not persistent and is destroyed when the last fd closes**. Under SIGKILL the kernel force-closes the fd, so the interface necessarily disappears.
  - When the interface disappears the kernel reclaims routes using it as output interface **immediately**, with no delay and no GC wait.
  - A control experiment confirms this is not "routes die with the process that created them": the same kind of route installed on `eth0`, a persistent interface, **still exists** after `kill -9`.

  **Design implication: route-side P2 is nearly free on Linux.** For routes, the `installed` state file degrades into insurance and drift healing (FR-8.4) rather than a necessity. It also explains why the existing `/32` zombie defect never showed up in production: this kernel behavior has been covering it.

  Two caveats remain:
  - **macOS and Windows are unverified**, so the same behavior cannot be assumed. M0 should repeat the experiment on each.
  - The conclusion **covers only routes whose output interface is the noeio TUN.** Rules pointing at a physical NIC, such as policy routing or `ip rule`, get no such protection if introduced later.

- **FR-8.8 NAT and sysctl side: residue verified on Linux.** Unlike routes, `sysctl` values are **confirmed unchanged after `kill -9`** (§12 experiment 4: 0 to 1, then killed, still 1). iptables and pf rules behave the same way, hanging off no process. This is where P2's real risk lives, and it requires convergence at startup:
  - **netfilter rules**: everything is written into noeio's dedicated `noeio` table (FR-5.8.5), and startup **deletes the whole table and rebuilds it**. That is idempotent by construction and **needs no state file**. Deleting the whole table is one atomic netlink operation, cleaner than flushing rule by rule, which is one of the payoffs of FR-5.8.5's choice of a dedicated table over custom chains in existing tables.
  - **sysctl** (`net.ipv4.ip_forward`, `net.inet.ip.forwarding`): write the original value into a run-state file, and restore it at startup if the last run did not.
  - **macOS pf**: load rules into their own anchor such as `noeio`, and flush that anchor at startup, so noeio and the user's existing pf configuration do not overwrite each other.

- **FR-8.9** The `installed` state file lives in `/var/run/noeio/`, on tmpfs so a reboot clears it, since after a reboot neither the interfaces nor the rules exist and a stale state file does more harm than good. A corrupt file or a version mismatch is treated as an empty set with a WARN, and must not fail startup.

  Given FR-8.7's verification results, **how necessary the file is depends on its contents**:
  - **Original sysctl values: required.** Without them there is no way to know what to restore, and this is the only piece of state where losing the information makes recovery impossible.
  - **netfilter rules: not needed.** The dedicated table plus whole-table rebuild at startup is already idempotent (FR-8.8).
  - **Route list: optional.** The kernel reclaims them on Linux; keeping the list serves FR-8.4's drift healing and acts as insurance while the macOS and Windows results are unknown.

- **FR-8.10** Give the `noeio` daemon a graceful exit: following the SIGTERM and ctrl_c handling in `noeio-derp/src/main.rs:158`, introduce a shutdown signal at `noeio/src/main.rs:37` and run one reconcile with `desired` emptied before exiting. This is P2's **best-effort path**, covering normal exits like systemd stop and ctrl_c, and cannot be the only safeguard.

- **FR-8.11** Implement `del_route` on all three platforms (`noeio-net-route`). This is the reconciler's prerequisite, so it is **promoted from "one item in M1" to an M1 blocker**. On macOS it can reuse the `PF_ROUTE` message construction in `macos.rs:16` `add_route` with `rtm_type` changed to `RTM_DELETE`.

#### 8.4 A note on priority

FR-8.5 layer 2, the derper tombstone, ranks **above SNAT** (FR-5). The reason is the difference in magnitude of consequence: a zombie `/32` makes one overlay IP unreachable, while a zombie `10.0.0.0/8` costs the Consumer access to **its entire 10.x production network**, including the parts that have nothing to do with noeio. An uninstall or disable operation would cause a production outage. That risk cannot wait for M3.

### FR-9 Advertiser rejection semantics on non-Linux platforms

Following FR-5.5: **the Advertiser capability is implemented on Linux only, and macOS and Windows nodes can only be Consumers.**

#### 9.1 Core principle: a warning is not a pass

- **FR-9.1** On non-Linux platforms an advertise request must both warn and not take effect. Specifically: the warning is emitted as usual, but the CIDR is **never written into `PeerInfo.advertised_routes`, so it never enters the broadcast path**.

  This is the crux of FR-9 and must not be weakened to "print a warning and carry on". If a macOS node warns once and broadcasts anyway, every Consumer in the network installs a route toward it, and traffic arriving there is dropped for lack of SNAT and forwarding. The symptom is that the prefix becomes a black hole for the entire network, and **the diagnostic trail is completely invisible on the affected nodes**: on the Consumer side everything looks fine, with the route installed, the tunnel up, and packets sent.

  Rejecting with a warning, by contrast, confines the impact to the single machine running the command, with the error message right in front of the operator. The two cost an order of magnitude apart.

- **FR-9.2** FR-1.5's validation checklist therefore **gains one leading rule on non-Linux platforms: the platform does not support Advertiser**. It goes through the same rejection path as the other validation rules and is not a special-case branch.

#### 9.2 Behavior at the three entry points

Advertising has three entry points (FR-1.1, FR-1.2, FR-1.3). All three behave consistently, none taking effect and all producing a visible message, but **the disposition differs**:

- **FR-9.3 Config file** (`[router] advertise_routes`): **fail startup and exit** with a non-zero code.

  The config file expresses a standing intent, and the user will assume it stays in effect. Warning and continuing would leave the node running in an apparently healthy state while the user believes subnet routing works. Failing at startup surfaces the mismatch between config and platform immediately. The error must name the platform and list the rejected CIDRs, and state plainly that this platform can only be a Consumer and that the prefix should be advertised from a Linux node.

- **FR-9.4 CLI startup flag** (`--advertise-routes`): same as FR-9.3, **fail startup and exit**. It shares the validation logic with the config file rather than reimplementing it.

- **FR-9.5 Runtime RPC** (`AdvertiseRoute`, M3): **does not exit the daemon**. It returns the gRPC status `FAILED_PRECONDITION` with the same actionable explanation.

  A Consumer already serving normally should not be interrupted by one mistaken RPC, since its overlay connectivity and accepted routes are all still working. The right behavior is to reject that one request rather than punish the whole process. The CLI renders the error as a human-readable message instead of surfacing the raw gRPC status.

- **FR-9.6** On non-Linux platforms `noeio route list` (FR-7.4) marks the node explicitly as **Consumer-only**, so whoever is troubleshooting knows this machine cannot be the advertiser without consulting the docs.

#### 9.3 Relationship to Consumer capability

- **FR-9.7** The restriction applies to advertising only. macOS and Windows have **full Consumer support**: accepting remote CIDRs, installing routes, longest-prefix-match forwarding, withdrawal, and convergence all work normally. §8.1.1 already notes that a pure Consumer touches neither sysctl nor iptables, so these platforms also carry the lightest cleanup burden.
- **FR-9.8** `accept_routes` behaves the same on every platform, with no platform-dependent variation.
- **FR-9.9** Wording: avoid phrasings like "subnet routing is not supported", which readers take to mean Consumer is unsupported too. The standard phrasing is "this platform cannot **advertise** subnet routes (Advertiser), and can normally **use** subnet routes advertised by other nodes (Consumer)".

## 6. Platform support matrix

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Consumer: install CIDR routes | ✅ `net-route` | ✅ `PF_ROUTE` (in-house, `noeio-net-route/src/macos.rs`) | ✅ `net-route` |
| Consumer: delete routes | to build (FR-8.11) | to build (`RTM_DELETE`) | to build (FR-8.11) |
| Kernel reclaims routes when the TUN disappears | ✅ **verified reclaimed** (§12) | ❓ unverified | ❓ unverified |
| sysctl / NAT rules die with the process | ❌ **verified to linger** (§12) | ❌ expected to linger | — |
| **Advertiser role overall** | ✅ **the only platform this cycle** | ❌ rejected with a warning (FR-9) | ❌ rejected with a warning (FR-9) |
| Advertiser: enable IP forwarding | ✅ sysctl | deferred | ❌ |
| Advertiser: SNAT | ✅ nf_tables via netlink (FR-5.8, no command-line dependency) | deferred (pf, FR-5.4) | ❌ |
| Advertiser: reply DNAT | ✅ conntrack, automatic | deferred | ❌ |
| Advertiser: MSS clamp | ✅ | deferred | ❌ |

How to read it: every Consumer row covers all three platforms, and every Advertiser row is Linux only. Advertise requests on non-Linux platforms are rejected per FR-9, warning without taking effect and without entering the broadcast path.

On Linux, if a system has only `nftables` and no `iptables-nft` compatibility layer, detect that and use the equivalent `nft` rules, or fail explicitly at startup.

## 7. Non-functional requirements

### 7.1 Security

- **S-1** The relaxed anti-spoofing check (FR-5.1) must be a strict whitelist of the CIDRs that peer advertised, and must not degrade into "do not check the inner source address".
- **S-2** `SyncRoute` only trusts packets from the currently configured derper. That check already exists (`noeio/src/daemon.rs:433`) and must not be bypassed by the refactor.
- **S-3** The derper relays routing information, so it is capable of forging advertised routes and hijacking a Consumer's traffic. This cycle accepts that trust assumption, consistent with the existing trust model for virtual IP allocation, but the docs must say so explicitly: **trusting the derper is equivalent to giving it write access to your routing table**.
- **S-4** FR-1.5's advertisement blacklist is the backstop against a misconfiguration stranding the node, so it must be validated on **both the Advertiser and the Consumer** rather than trusting that the remote already did it.
- **S-5** Enabling `ip_forward` on the Advertiser changes the networking behavior of the whole host, not just noeio's traffic. Log a WARN when enabling it and explain it in the docs.
- **S-6** FR-5.8's netlink approach removes the command injection surface entirely. Rules are installed as binary attribute encodings, with no shell and no string concatenation, and CIDRs and interface names from a remote `PeerInfo` go into netlink attributes as numbers or bytes directly. This is a side benefit of choosing netlink over the command line.

  Still worth noting: `sysctl` implemented by writing `/proc/sys/...` (the recommended way) also involves no shell, but **interface names and CIDRs still need format and range validation before encoding**, because they come from an untrusted remote `PeerInfo`. If an overlong input pollutes a netlink attribute length field, the risk shifts from injection to constructing a malformed netlink message. Validation is still required; only the threat model changes.

### 7.2 Performance

- **P-1** The added cost of the outbound `lookup` over the existing `DashMap::get` should be negligible in pure host-route scenarios, since the exact table hits first and the prefix table is never touched.
- **P-2** Subnet routing introduces no extra memory copies; under the kernel-assisted approach forwarding happens in the kernel and adds no userspace cost.
- **P-3** A route table change, added or withdrawn, must not block the forwarding path for longer than a single read lock acquisition.

### 7.3 Observability

- **O-1** `route list` exposes the full route state (FR-7.4).
- **O-2** Structured logs for every key event: route learned, installation succeeded or failed, conflict rejected, withdrawal, active egress failover, AllowedIPs drop.
- **O-3** AllowedIPs drop counts are aggregated by `peer_id` so one misconfigured peer cannot flood the log. The current `warn!` at `daemon.rs:596` is unthrottled, and with subnet routing it needs rate limiting or a counter instead.

### 7.4 Compatibility

- **C-1** Mixed old and new versions must never cause a parse failure or a panic (FR-2.2).
- **C-2** With no `advertise_routes` and `accept_routes = false`, behavior is **identical to the current version**: no new rules installed, no sysctl modified. This is the default configuration.
- **C-3** The Advertiser's minimum kernel is **4.18** (FR-5.8.11). The Consumer path introduces no new kernel requirement, since it only uses the routing table, same as today. Raising the kernel floor therefore **only affects nodes that want to be subnet routers** and does not affect upgrading existing deployments. Make this distinction clear in the release notes.

## 8. Acceptance criteria

### 8.1 End to end

- **AC-1** Topology: Consumer E, Advertiser A, and agentless host B on A's LAN. After A advertises B's prefix, `ping B` and `curl http://B` both succeed on E, and a capture on B shows A's LAN address as the source (SNAT working).
- **AC-2** After A withdraws the advertisement, the corresponding route on E disappears within one report interval (≤ 10 s) plus reasonable slack, `ping B` fails, and the rest of E's local networking is unaffected.
- **AC-3** After A and E switch from direct to derper relay (by blocking direct UDP), subnet traffic still flows, since link selection reuses the existing machinery.
- **AC-4** Large response test: downloading a file of ≥ 10 MB from B succeeds on E, with no "handshake succeeds but the transfer hangs" MTU black hole (verifies FR-5.7).
- **AC-5** When two nodes advertise the same CIDR, E installs exactly one active route, and failover to the other happens automatically when the active Advertiser goes offline.
- **AC-6** After both A and E exit **normally** (SIGTERM), the system routing table, the iptables custom chains, and sysctl all return to their pre-startup state.
- **AC-6b** After `kill -9` on E and then **restarting** the daemon, convergence at startup leaves the system clean: no leftover CIDR routes, empty `NOEIO_*` chains, `ip_forward` back to its original value (verifies FR-8.7 through FR-8.9).
- **AC-6c** After Advertiser A is `kill -9`ed, with no restart and no withdrawal message sent, the corresponding subnet route on E disappears within the derper TTL plus the convergence interval, and E's **pre-existing local reachability for that CIDR is undamaged** (verifies FR-8.5 layer 2, the tombstone mechanism).

### 8.2 Unit and integration tests

- **AC-7** `Router::lookup` coverage: exact match beats prefix match, longest-prefix match is correct, no match returns `None`, containing CIDRs, and concurrent read/write safety on the prefix table.
- **AC-8** `PeerInfo` serialization round trip: protobuf conversion both ways with and without `advertised_routes`, plus parsing an old message that lacks the field.
- **AC-9** AllowedIPs check: an inner source IP inside an advertised CIDR passes, one outside is dropped, one equal to the peer's virtual IP passes.
- **AC-10** Every case in FR-1.4 and FR-1.5's CIDR validation, including the rejection path where a derper address falls inside an advertised CIDR.
- **AC-11** `del_route` add/delete round trip on each of the three platforms. Requires privileges, so mark as ignored or run inside a CI container.
- **AC-13** Unit tests for the reconciler's pure function (`desired = f(Router)`): peer added, CIDR withdrawn, peer tombstoned, accept policy disabled, each producing the correct diff (add set and delete set).
- **AC-14** **No spurious deletion while stable** (guards FR-8.6): construct a peer with learned routes, then produce no further `SyncRoute` at all, simulating the derper's `resource_version` deduplication, advance time, and assert the routes **are not withdrawn**. This guards the most likely serious bug in the feature.
- **AC-15** Reconcile idempotence: two consecutive reconciles, the second producing an empty diff; after an external manual route deletion, the next reconcile restores it.
- **AC-12** Regression: with `accept_routes = false` and no `advertise_routes`, all existing tests pass and no new syscalls appear.
- **AC-16 Non-Linux advertise rejection (guards FR-9.1)**: on macOS and Windows, configure `advertise_routes` or call `AdvertiseRoute`, and assert that
  1. the startup path (config file or CLI flag) exits non-zero with an error naming the platform and the rejected CIDRs;
  2. the RPC path returns `FAILED_PRECONDITION` and **the daemon keeps running**;
  3. **the CIDR never appears in `PeerInfo.advertised_routes`**. This is the most important assertion here, guarding directly against the most dangerous implementation slip, "warn and broadcast anyway". This can be asserted against the constructed `PeerInfo` in a unit test, with no real multi-platform environment needed.
- **AC-17** Full regression of Consumer capability on non-Linux platforms (FR-9.7): accepting remote CIDRs, installing routes, LPM forwarding, and withdrawal convergence all work, proving FR-9's restriction did not spill into the Consumer path.
- **AC-18 netfilter rule read-back (guards Q10)**: after installing rules, **read them back over netlink and assert their content**: the table exists, the chain's hook and priority are right, the masquerade expression is present. **Asserting that the install call returned `Ok` is not enough**: the classic failure mode of a hand-built ABI encoding layer is "the kernel accepted the message but the rule does not mean what you intended", and only a read-back catches that silent failure.
- **AC-19** Whole-table rebuild idempotence (FR-8.8): running "delete table, create table, install rules" twice in a row yields an identical ruleset, and deleting a table that does not exist is not an error.
- **AC-20** No command-line dependency (guards FR-5.8.1): complete the end-to-end SNAT verification inside a minimal image containing **no `iptables`, `nft`, or `ip` binary**. The build image used in §12 happens to satisfy this and can be reused directly.

## 9. Risks and open questions

| # | Question | Detail | Leaning |
| --- | --- | --- | --- |
| Q1 | Kernel conntrack or a userspace NAT table for SNAT? | The kernel approach is an order of magnitude less code, gets state maintenance for free, and performs better, but binds to Linux and macOS and requires privileges to change a global sysctl. The userspace approach is controllable, cross-platform, and more observable, but needs a port pool, aging, checksum recomputation, and raw socket injection, several times the work. The original requirement described "noeio maintains SNAT rules", which supports either reading | Kernel approach in M1, userspace NAT as a separate later item |
| Q2 | `smoltcp::wire::Ipv4Cidr` or add `ipnet` for the CIDR type? | The former adds no dependency but has a thin API (parsing and containment need a layer of your own); the latter has a complete API and friendlier serialization | Try `smoltcp` first, add `ipnet` if it falls short |
| Q3 | Should the derper validate advertised routes? | The derper is a pure pass-through today. Validation would catch misconfigurations but pushes network policy down into the relay and increases coupling | Not this cycle; validate on both Advertiser and Consumer (S-4) |
| Q4 | What to do with `noeio-derp/src/router/delta.rs`? | Eight lines of dead code, not referenced by `main.rs`'s `mod` list, all fields private with no impl. FR-2.5's full-diff requirement lands squarely on the problem it was meant to solve | Either delete it or rewrite it as real incremental sync; do not leave it |
| Q5 | `Router::remove` and `NicManager::remove` are defined but never called | An existing defect that subnet routing amplifies. §FR-8 gives the approach (reconciler) | See FR-8.2 |
| Q7 | Does the kernel reclaim a TUN's routes when it disappears? | **Verified on Linux: yes** (§12). Route-side P2 is nearly free; sysctl is confirmed to linger and is the real risk | **Closed** for Linux. macOS and Windows each still need one run in M0 |
| Q9 | How do netfilter rules get installed? | Four candidates: `rustables` (pure Rust netlink, complete NAT support, but **GPL-3.0, conflicting with this project's Apache-2.0**), `nftnl` (Mullvad, FFI to libnftnl plus libmnl, no vendoring, expensive to cross-compile), the `nftables` crate (MIT but shells out to `nft`), the `iptables` crate (a `Command` wrapper). All detailed in FR-5.8 | **Decided: build a minimal nf_tables encoding layer** on `netlink-packet-netfilter` (MIT). The most work, but a clean license, no C dependency, no runtime binary, and consistent with `noeio-net-route`'s existing convention |
| Q10 | ABI correctness risk in a hand-built encoding layer | An error in hand-encoded expressions can surface as "the rule installed fine but does nothing", a silent failure harder to find than a compile error. The risk is lower than first estimated, since the crate already provides attribute encode/decode plus byte-level test templates (`src/nftables/tests.rs`) | Needs an integration test that **reads the rules back over netlink and asserts their content** rather than just asserting the call succeeded. See NFAC-1 / NFAC-2 in the [nf_tables document](../nftables-netlink-requirements.en.md) |
| Q8 | A `withdrawn` flag on `SyncRoute` or a new `PeerGone` packet type for the derper tombstone? | The former reuses the existing message and broadcast path and is a smaller change; the latter is semantically cleaner but touches the `NoeioPacketType` enum (`noeio-common/src/packet.rs:12`) and has to account for how old nodes treat an unknown type | Leaning toward the flag, since old nodes ignore unknown fields and degrade to current behavior |
| Q6 | Subnet hosts initiating traffic to overlay nodes | A non-goal, but users will very likely ask. It needs reverse DNAT plus port mapping on the Advertiser, or bidirectional routing, and the design is entirely different | Explicitly labeled a later feature |

## 10. Milestones

**M0: prerequisite verification and the cleanup skeleton (blocks M1)**
1. ~~Verify FR-8.7 on Linux~~: **done**, see §12. Remaining: one run each on macOS and Windows.
2. FR-8.11: `del_route` on all three platforms.
3. FR-8.10: SIGTERM and ctrl_c handling in the daemon (`noeio/src/main.rs` has none today).
4. FR-8.2 / FR-8.3: the reconciler skeleton, starting by migrating the **existing `/32` host routes** onto it.

This step contains no subnet routing functionality, but it corrects the "add with no delete" shape first and fixes the existing `/32` zombie defect along the way.
Acceptance: AC-13, AC-14, AC-15, AC-11, plus a full regression of the existing `/32` scenario.

**M1: the routing plane end to end (no NAT)**
FR-2 (protocol field plus broadcast), FR-2.5 / FR-8.5 layer 1 (full-diff withdrawal), FR-4 (`Router` LPM plus `process_outbound`), FR-5.1 (AllowedIPs), FR-3.2 (CIDR routes, reusing M0's reconciler), FR-1.1 / FR-1.4 / FR-1.5 (configuration and validation), **FR-9.1 through FR-9.4 and FR-9.9 (non-Linux advertise rejection: startup paths, staying out of the broadcast path, wording)**.

> FR-9's startup path **must land in M1** and cannot slip to M3. By the end of M1 the advertisement path is connected end to end, and a non-Linux platform that can still broadcast a CIDR at that point already has everything it needs to create a network-wide black hole (FR-9.1). The RPC entry point's rejection (FR-9.5 / FR-9.6) ships with the RPC work in M3.
Acceptance: between two noeio nodes, A advertises a CIDR other than its own `/32`, and packets E sends to that CIDR reach A's TUN (verified with tcpdump), with no requirement that A forward them onward; after A withdraws, the route on E disappears.

**M1.5: the derper tombstone (ahead of SNAT, see §FR-8.4)**
FR-8.5 layer 2 (moka eviction listener plus tombstone broadcast), settling Q8, FR-8.5 layer 3 backstop.
Acceptance: AC-6c. The reasoning is in FR-8.4: without this layer, a remote losing power leaves an entire prefix black-holed on the Consumer.

**M2: Advertiser forwarding and SNAT (Linux only)**
**FR-5.8 (the minimal nf_tables netlink encoding layer, this milestone's main effort and main risk)**, FR-5.3 (ip_forward plus masquerade plus forward acceptance), FR-5.5 (the platform restriction), FR-5.7 (MSS clamp), FR-6.1, FR-8.8 / FR-8.9 (startup convergence for the netfilter table and sysctl), FR-5.6 (privilege and kernel capability error messages).
Acceptance: AC-1, AC-2, AC-4, AC-6, AC-6b, AC-16, AC-18.

> M2's center of gravity shifts from "assemble a few iptables commands" to "build a netlink encoding layer", so it is worth splitting internally: first get table creation, chain creation, and one masquerade rule working with a read-back assertion (AC-18), then add ct state, MSS clamp, and whole-table rebuild.

**M3: control plane**
FR-7 (RPC and CLI), FR-9.5 / FR-9.6 (RPC rejection plus the Consumer-only marker in `route list`), FR-1.2 / FR-1.3, FR-3.4 (conflicts and active/standby failover), FR-2.6, O-1 through O-3.
Acceptance: AC-3, AC-5, AC-17, plus a full regression.

> The macOS pf implementation (FR-5.4) from the original "M3: control plane and multi-platform" has moved out of this cycle's scope, see FR-5.5. There is no "multi-platform Advertiser" goal this cycle.

## 11. Summary of existing code touch points

In data flow order, to make PR splitting easier:

| # | Location | Change | Milestone |
| --- | --- | --- | --- |
| 1 | `noeio-proto/protos/common/v1/host_info.proto:5` | `PeerInfo` gains `repeated string advertised_routes = 8` | M1 |
| 2 | `noeio-common/src/host_info.rs:72` and both proto conversions | New `PeerInfo` field, constructor, compatible parsing | M1 |
| 3 | `noeio/src/config.rs:4`, `noeio/src/cli.rs:15`, `config.toml.example` | The `[router]` config section, CLI flags, merge logic | M1 / M3 |
| 4 | `noeio/src/daemon.rs:97` (`register_nic`) and `:260` (`register_host_info`) | Populate local advertised routes; bump `HostInfo.resource_version` on change | M1 |
| 4b | Same, the validation gate before population (a separate function is suggested, colocated with FR-1.5's blacklist) | Under `#[cfg(not(target_os = "linux"))]` the advertise list is always empty. This is the **only place that can guarantee "never enters the broadcast path"** (FR-9.1). The startup paths handle exit separately in `config.rs` / `main.rs` (FR-9.3 / FR-9.4) | M1 |
| 5 | `noeio/src/daemon.rs:430` (the `SyncRoute` branch) | Full diff of remote CIDRs; update `Router.subnets` and notify the reconciler only, **no more imperative installation** (FR-8.1) | M1 |
| 6 | `noeio/src/daemon/router.rs:17` | Add the `subnets` prefix table plus `lookup()` LPM | M1 |
| 7 | `noeio/src/daemon.rs:187` (`process_outbound`) | `router.get` becomes `router.lookup`; miss log downgraded | M1 |
| 8 | `noeio/src/daemon.rs:593` (`handle_delivery`) | Anti-spoofing becomes AllowedIPs semantics; drop log rate limited | M1 |
| 9 | `noeio/src/daemon/nic.rs:18`, `noeio/src/interface/virtual_nic.rs:42` | `route` accepts a non-`/32` netmask (the net-route layer already supports it; only parameterization is needed) | M1 |
| 9b | `noeio/src/interface/virtual_nic.rs:55` (`create_tun`) | Add a comment: the TUN must stay **non-persistent** (`IFF_PERSIST` = 0). §12's zombie route conclusion depends entirely on this property, and switching to a persistent TUN invalidates it immediately | M0 |
| 10 | `noeio-net-route/src/lib.rs`, `macos.rs:16` | Add `del_route` on all three platforms; macOS reuses the `PF_ROUTE` message construction with `rtm_type` set to `RTM_DELETE` | **M0** |
| 10b | `noeio/src/main.rs:37` | Add SIGTERM and ctrl_c handling (none today), following `noeio-derp/src/main.rs:158` | **M0** |
| 10c | New `noeio/src/daemon/reconciler.rs` (or folded into `nic.rs`) | desired / installed state convergence; `/32` host routes migrate onto it first | **M0** |
| 10d | `noeio-derp/src/connection/peer.rs:38` and `handle_sync` in `connection.rs` | moka eviction listener plus tombstone broadcast (FR-8.5 layer 2) | M1.5 |
| 11 | New `nftables/` in `noeio-net-route` (the minimal nf_tables netlink encoding layer) plus `nat.rs` and `forwarding.rs` | The dedicated `noeio` table, masquerade / ct state / MSS clamp expressions, atomic whole-table rebuild, `ip_forward` read and written through `/proc/sys` with the original value saved. **Depends on `netlink-packet-netfilter` (MIT), with no C library and no runtime binary** (FR-5.8) | M2 |
| 11b | The module docs at `noeio-net-route/src/lib.rs:3` | Extend the existing convention to bring netfilter rules under "no binary needed at runtime", and note that `rustables` is unusable because GPL-3.0 conflicts with this project's Apache-2.0 (FR-5.8.3) | M2 |
| 12 | New `noeio-proto/protos/noeio/v1/route.proto` plus `noeio/src/rpc/service/route.rs`, `rpc/service.rs:13`, `rpc/client.rs:8`, `cli.rs`, `main.rs` | Route management RPC and CLI; `AdvertiseRoute` returns `FAILED_PRECONDITION` on non-Linux without exiting the process (FR-9.5), and `route list` marks Consumer-only (FR-9.6) | M3 |
| 13 | `noeio-derp/src/router/delta.rs` | Dead code: delete it or rewrite it as incremental sync (Q4) | M3 |
| 14 | `noeio/src/daemon/router.rs:74`, `noeio/src/daemon/nic.rs:51` | `remove` is defined with no callers today; wire it into the reconciler's delete path (Q5) | M0 / M1 |

On the scope of derper changes, two things need separating:

- **Broadcasting advertised routes**: `Report` and `handle_sync` need **no changes**, since the new `PeerInfo` field passes through the existing protobuf payload automatically.
- **The tombstone mechanism**: the derper **must change** (row 10d). This is a protocol gap, and no amount of Consumer-side work can discover that a remote lost power. See FR-8.5 and FR-8.6.

## 12. Appendix: verification record for P2 residue behavior

Verification date: 2026-09-22. Environment: Docker, OrbStack Linux kernel `6.17.4` aarch64, `--privileged`.
Method: reproduce noeio's real call path in Rust. The TUN configuration copies `create_tun` at `noeio/src/interface/virtual_nic.rs:55` (L3, MTU 1411, `/32` netmask, `tun_name`), and route installation copies `net_route::Route::new(...).with_ifindex(...).with_metric(...)` at `noeio-net-route/src/lib.rs:18`. The routing table is read directly from `/proc/net/route`, since the image has no `ip` or `iptables` binary.

### Experiment 1: TUN route plus `kill -9`

Install `10.99.0.0/24` via TUN `noeio0` (ifindex 6), then `kill -9`:

```
while-alive:   iface=noeio0  dst=10.99.0.0/24  metric=7
               interfaces: eth0 lo noeio0 ...

after kill -9: (10.99.0.0/24 gone)
               interfaces: eth0 lo ...          <- noeio0 gone too
after +5s:     (still gone)
```

The route and the interface disappear together, immediately. STEP 4 is already clean, so there is no delayed GC window.

### Experiment 2: control group, route via eth0 plus `kill -9`

This rules out the confounding variable "do routes just die with the process that created them". Install `10.88.0.0/24` via `eth0`, a persistent interface, then `kill -9` the same way:

```
while-alive:   iface=eth0  dst=10.88.0.0/24  metric=7
after kill -9: iface=eth0  dst=10.88.0.0/24  metric=7   <- still there
after +5s:     iface=eth0  dst=10.88.0.0/24  metric=7   <- still there
```

**Routes do not die with the process.** The disappearance in experiment 1 is therefore attributable to the interface disappearing, not to process exit.

### Experiment 3: mechanism, why the TUN disappears

```
/sys/class/net/noeio0/tun_flags = 0x1001
```

`IFF_PERSIST` is `0x0800`, and that bit is **0**. The device noeio creates through the `tun` crate is **not persistent** and is destroyed when the last fd closes; under SIGKILL the kernel force-closes the fd, so the interface necessarily disappears. That is a mechanistic explanation, not just one observation.

> Switching to a persistent TUN later (`ip tuntap add ... mode tun` or setting `IFF_PERSIST` explicitly) **invalidates this section immediately**, and zombie routes become a real problem. This is an implicit constraint worth marking in a code comment.

### Experiment 4: does sysctl linger?

The first attempt was void: the container baseline for `ip_forward` was already `1`, and going from 1 to 1 verifies nothing. Corrected by forcing the baseline to `0`:

```
baseline (forced):            ip_forward = 0
during (advertiser running):  ip_forward = 1
after kill -9:                ip_forward = 1     <- lingers
```

**Residue confirmed.** iptables and pf rules behave the same, hanging off no process. This is where P2's real risk lives, and it maps to FR-8.8 and FR-8.9.

### Summary of conclusions

| State type | After `kill -9` | Design implication |
| --- | --- | --- |
| Routes via the TUN (Linux) | **reclaimed automatically** | Route-side P2 is nearly free; the state file drops to insurance |
| Routes via a physical NIC | linger | Such rules, if introduced, get no kernel protection |
| sysctl `ip_forward` | **lingers** | Original value must be persisted and restored at startup |
| iptables / pf rules | linger | Own chain plus a flush at startup, idempotent, no state file needed |

One thing this explains along the way: the existing `/32` host route zombie defect (`Router::remove` and `NicManager::remove` never being called) went unnoticed in production precisely because the kernel reclamation above was covering it. That lowers the legacy risk but **does not change FR-8.1's conclusion**, since P1, withdrawal while the process lives, gets none of that protection, and P1's consequence with subnet routing is an entire prefix going dark.

### Not covered

- **macOS and Windows are unverified**, so the same behavior cannot be assumed. But since FR-5.5 limits the Advertiser to Linux and those two platforms are Consumers only, touching just the routing table and never sysctl or iptables, **this no longer blocks the cycle** and drops to a leftover: run it once on each during M0 (on macOS with `netstat -rn` plus `ifconfig`) so the data exists when macOS Advertiser support opens up later.
- The device lifecycle of the `tun` crate on **Windows** (the wintun adapter) is unverified, and its model differs considerably from Unix TUN.
- Not verified under real systemd (PID 1 and reaper behavior differ inside a container), though since the conclusion rests on the kernel semantics of fd closure, it is expected to hold.
