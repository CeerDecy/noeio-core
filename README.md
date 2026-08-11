# Noeio Core

![Rust](https://img.shields.io/badge/Rust-1.94%2B-black?logo=rust&logoColor=white)

English | [简体中文](README.zh-CN.md)

Noeio is a self-hostable layer-3 mesh networking system. It connects machines across LANs, NATs, and clouds into one private network over a virtual NIC. All data-plane components run on your own infrastructure; no third-party coordination service is involved.

## Features

- **Layer-3 virtual NIC** — peers join a private subnet through a local `noeio0` interface; any IP traffic just works
- **WireGuard-encrypted data plane** — a dedicated tunnel with per-peer keys between every pair of nodes, powered by boringtun
- **NAT traversal** — STUN-based address discovery and UDP hole punching for direct connections across NATs
- **Lowest-latency path selection** — every candidate path (LAN and public) is probed with ping/pong RTT sampling, and traffic always takes the fastest one, with debounced switching
- **Self-hosted relay fallback** — when no direct path exists, traffic falls back to your own derper relay, guarded by network-scoped token auth
- **Cross-platform** — runs on Linux, macOS, and Windows

## Motivation

It was after using [Tailscale](https://github.com/tailscale/tailscale) that I discovered how powerful and remarkably easy to use it is. Out of a desire to learn, I dug into the principles behind its implementation, and found they happened to resemble the Kubernetes CNI plugins I was studying at the time. So, to learn more and round out my networking knowledge, I decided to write an overlay network of my own. I know this project may never rival Tailscale, but the learning process alone has been richly rewarding. I hope to share it as the outcome of that learning, to exchange and discuss more knowledge and interesting ideas with the community.

## Differences from Tailscale

Noeio is a pure data-plane component: it only handles networking itself, and ships none of the account, identity, or ACL machinery that Tailscale builds in. This makes it well suited for self-hosted deployment. If you need multi-tenancy, pair it with your own control plane on top.

## Architecture

![Noeio architecture](docs/images/screenshot-20260811-152405.png)

Each node runs a noeio daemon that reports its addresses and NAT type to the self-hosted derper; the derper broadcasts every peer's route candidates back via SyncRoute. Traffic between nodes takes a WireGuard-encrypted direct path whenever one exists, and falls back to relaying through the derper otherwise.

## Install

Prerequisites: the [Rust toolchain](https://rustup.rs/) and `protoc` (the protobuf compiler) — `apt install protobuf-compiler` on Linux, `brew install protobuf` on macOS; on Windows use `choco install protoc` / `scoop install protobuf`, or download a `protoc-*-win64.zip` from the [protobuf releases](https://github.com/protocolbuffers/protobuf/releases) and add it to your `PATH`. Binaries are compiled locally by cargo, so this works on any platform.

### derper

The derper must be deployed on a machine reachable by every node — typically a cloud instance with a public IP:

```bash
cargo install --git https://github.com/CeerDecy/noeio-core noeio-derp
```

### noeio

Install the noeio daemon on every node that joins the virtual network:

```bash
cargo install --git https://github.com/CeerDecy/noeio-core noeio
```

## Quick start

1. Start a derper relay. The derper must be deployed on a machine reachable by every node — typically a cloud instance with a public IP.

   With Docker:

   ```bash
   docker run -d --name noeio-derper -p 8080:8080/udp --rm registry.cn-hangzhou.aliyuncs.com/noeio/noeio-derp:202608111410-bd5e900
   ```

   Or with the binary:

   ```bash
   cargo install --git https://github.com/CeerDecy/noeio-core noeio-derp && noeio-derp boot
   ```

2. Create a derper auth token for your network. `--network` takes a UUID that identifies a virtual network — feel free to use any UUID of your own; nodes holding a token for the same UUID join the same network.

   With Docker:

   ```bash
   docker exec noeio-derper /usr/local/bin/noeio-derp token create --network 25fe8468-b310-43ed-96be-495641eececd --ttl 0
   ```

   Or with the binary:

   ```bash
   noeio-derp token create --network 25fe8468-b310-43ed-96be-495641eececd --ttl 0
   ```

3. On every node that should join the virtual network, update `~/.noeio/config.toml` — make sure to replace `address` with your own derper's address and `token` with the token created in step 2:

   ```toml
   [stun]
   servers = ["stun.chat.bilibili.com:3478"] # change to a STUN server near you

   [[derper.servers]]
   address = "192.168.0.1:8080" # change to your own derper address
   token = "<replace with the token from step 2>"
   ```

4. Start the noeio daemon (binary only):

   ```bash
   noeio boot
   ```

   > Running the noeio daemon itself in Docker is not recommended on non-Linux hosts: virtual NIC creation differs per operating system, and the default Docker image ships the Linux flavor.

5. Create a virtual NIC and join the network. `--ip` is up to you — the `100.64.0.0/10` range is recommended, and every node in the same network must use a different IP. `--network` must match the UUID used in step 2.

   On node A:

   ```bash
   noeio create vnic --ip 100.64.0.1 --network 25fe8468-b310-43ed-96be-495641eececd
   ```

   On node B:

   ```bash
   noeio create vnic --ip 100.64.0.2 --network 25fe8468-b310-43ed-96be-495641eececd
   ```

6. Try pinging node B from node A over the virtual network:

   ```bash
   ping 100.64.0.2
   ```

   ```text
   64 bytes from 100.64.0.2: icmp_seq=1 ttl=64 time=34.155 ms
   64 bytes from 100.64.0.2: icmp_seq=2 ttl=64 time=28.900 ms
   64 bytes from 100.64.0.2: icmp_seq=3 ttl=64 time=23.171 ms
   64 bytes from 100.64.0.2: icmp_seq=4 ttl=64 time=31.013 ms
   64 bytes from 100.64.0.2: icmp_seq=5 ttl=64 time=26.343 ms
   64 bytes from 100.64.0.2: icmp_seq=6 ttl=64 time=29.072 ms
   64 bytes from 100.64.0.2: icmp_seq=7 ttl=64 time=22.765 ms
   ```

   If the ping succeeds, the two nodes are connected — you're all set.

## Build

Build the derper binary:

```bash
cargo build --release -p noeio-derp
```

Or build and push a multi-platform Docker image:

```bash
REGISTRY=<your image registry url> MODEL=noeio-derp make build
```

Build the noeio daemon binary:

```bash
cargo build --release -p noeio
```

## Roadmap

- [ ] Zero-copy refactor of `NoeioPacket`
- [ ] Subnet routing support
- [ ] Multiple virtual network support

## License

This project is licensed under the [Apache License 2.0](LICENSE).
