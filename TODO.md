# NoeioPacket 零拷贝改造 TODO

## 阶段一：拿掉明显无谓的 `to_vec()`（无结构改动，纯收益）

- [ ] `noeio-derp/src/connection.rs:127` Forward 转发：把 `packet.inner.to_vec()` 换成 `&packet.inner[..]`，`UdpSocket::send_to` 直接接 `&[u8]`
- [ ] `noeio/src/tunnel/session/udp.rs:204,242,291` 控制包发送：`packet.inner.to_vec()` 同样换成借用切片送入 out_tx
- [ ] `noeio/src/daemon.rs:171,218` 出站 `NoeioPacket::new(...).into()` 后传给 `common_send`：让 `common_send` 收 `&NoeioPacket` 或 `&[u8]`，避免 `Into<Vec<u8>>` 那次 `to_vec`
- [ ] `noeio/src/daemon.rs:288-291` Forward 入站分支：`payload.to_vec()` 换成 `packet.payload()` 借用切片直接写 TUN
- [ ] `noeio-common/src/packet.rs:326-332` `TryFrom<[u8; N]>`：去掉先 `to_vec` 再走 slice 路径的双重拷贝，直接构造 `BytesMut`
- [ ] `noeio-derp/src/connection.rs:244-245` `handle_udp_recv`：去掉 `data.to_vec()`，直接 `NoeioPacket::try_from(data)`

## 阶段二：`Bytes` 引用计数替换 `Vec<u8>` 传递（小改，去掉通道 clone 的深拷）

- [ ] `noeio-common/src/packet.rs:159` `NoeioPacket.inner` 保留 `BytesMut`，但为读路径新增 `into_bytes(self) -> Bytes` / `as_bytes(&self) -> &Bytes` 接口
- [ ] `noeio-derp/src/main.rs:30` broadcast channel 类型改为 `(SocketAddr, Arc<NoeioPacket>)` 或直接传 `Bytes`，让订阅者 clone 只增引用计数
- [ ] `noeio/src/tunnel/session.rs:12` `Datagram = (Vec<u8>, SocketAddr)` 改为 `(Bytes, SocketAddr)`，`dispatch_signalling`（daemon.rs:458）去掉 `to_vec`
- [ ] `noeio-common/src/packet.rs:223` `payload()` 补一个返回 `Bytes` 的版本（`inner.slice(PAYLOAD_OFFSET..)`），用于跨任务传递场景

## 阶段三：headroom 预留，消灭组装拷贝（需改 I/O 读法）

- [ ] 读 TUN 时用 `BytesMut::with_capacity(PAYLOAD_OFFSET + MTU)`，`advance(PAYLOAD_OFFSET)` 后 `read` 到尾部；组装 header 用 `split_to` 反向拼接，`NoeioPacket::new` 零拷贝构造
- [ ] macOS 的 4 字节 AF 前缀（daemon.rs:299-305）同样用 headroom 预留，去掉那次 `Vec::with_capacity + extend_from_slice`
- [ ] `recv_from` 侧接收也用预留 headroom 的 `BytesMut`，为未来转发直接复用同一块内存做准备

## 阶段四（可选，性价比低）：极致零拷贝

- [ ] 引入 buffer pool（`bytes::BytesMut` 复用 or `crossbeam` 对象池），避免每次 recv 都 alloc
- [ ] 评估 `recvmmsg` / `sendmmsg` 批量收发（Linux）
- [ ] 评估 `io_uring`（Linux）/ `AF_XDP` 方案 —— 需要重写 I/O 层，仅在 derper 成为瓶颈时考虑

## 验收

- [ ] 出站单跳（TUN 读 → UDP 发）拷贝次数从 3+ 降到 1（kernel→user recv 那次不可避免）
- [ ] derper 转发（recv → send_to）拷贝次数从 3 降到 1
- [ ] 入站单跳（UDP recv → TUN 写）拷贝次数从 3 降到 1
- [ ] 增加 `cargo bench` 覆盖 packet 构造 / 解析 / 转发路径，前后对比
