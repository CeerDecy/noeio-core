use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use noeio_common::packet::{NoeioPacket, NoeioPacketType, PacketHeader};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};

/// How often keepalive packets are sent while the connection is alive.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// A peer connection (its [`SocketAddr`] plus the [`UdpSocket`] used to reach it)
/// that is kept only while the connection is actively used.
///
/// The connection is held behind an [`Arc<Mutex<Option<Connection>>>`]. A
/// background task drops it (sets it to `None`) once `ttl` elapses without any
/// [`access`](IdleConnectionGuard::access) call. Every access resets the timer,
/// so an actively used connection is never reclaimed. Once dropped, it is gone
/// for good — [`access`] returns `None` and [`is_alive`] reports `false`.
///
/// This is useful for lazily-held peer endpoints (e.g. a direct UDP path) that
/// should be released when the connection goes idle but kept warm under load.
pub struct IdleConnectionGuard {
    inner: Arc<Mutex<Option<Connection>>>,
    notify: Arc<Notify>,
}

/// The guarded resource: a peer's address and the socket used to reach it.
#[derive(Clone)]
pub struct Connection {
    /// The peer's UDP endpoint.
    pub addr: SocketAddr,
    /// The socket over which traffic to `addr` is sent.
    pub socket: Arc<UdpSocket>,
}

impl IdleConnectionGuard {
    /// Wrap the connection to `addr` over `socket`, reclaiming it after `ttl` of
    /// inactivity.
    ///
    /// Spawns a background task on the current Tokio runtime that watches for
    /// idleness; it exits as soon as the connection is dropped.
    pub fn new(addr: SocketAddr, socket: Arc<UdpSocket>, ttl: Duration) -> Self {
        let inner = Arc::new(Mutex::new(Some(Connection { addr, socket })));
        let notify = Arc::new(Notify::new());

        let inner_clone = Arc::clone(&inner);
        let notify_clone = Arc::clone(&notify);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(ttl) => {
                        // Idle for the full ttl: reclaim the connection and stop.
                        let mut lock = inner_clone.lock().await;
                        *lock = None;
                        tracing::debug!("IdleConnectionGuard connection expired after {:?}", ttl);
                        break;
                    }
                    _ = notify_clone.notified() => {
                        // Accessed within the window: restart the timer.
                        continue;
                    }
                }
            }
        });

        // Keep the peer's NAT mapping warm while the connection is alive.
        Self::keepalive(Arc::clone(&inner));

        Self { inner, notify }
    }

    /// Send keepalive packets to the peer until the connection is reclaimed.
    ///
    /// Runs on the current Tokio runtime and stops as soon as the guarded
    /// connection has been dropped (i.e. once `ttl` of inactivity elapses). This
    /// deliberately does *not* renew the idle timer — it keeps the NAT mapping
    /// warm without preventing an otherwise-idle connection from expiring.
    fn keepalive(inner: Arc<Mutex<Option<Connection>>>) {
        tokio::spawn(async move {
            let header = PacketHeader {
                packet_type: NoeioPacketType::Ping,
                peer_id: 0,
                port: 0,
            };
            let bytes: Vec<u8> = NoeioPacket::new(header, &[]).into();

            loop {
                // Snapshot the connection without renewing the idle timer.
                let conn = {
                    let lock = inner.lock().await;
                    match lock.as_ref() {
                        Some(conn) => conn.clone(),
                        None => break, // reclaimed: stop keeping alive.
                    }
                };

                if let Err(e) = conn.socket.send_to(&bytes, conn.addr).await {
                    tracing::warn!("IdleConnectionGuard keepalive to {} failed: {e}", conn.addr);
                }

                tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            }

            tracing::debug!("IdleConnectionGuard keepalive stopped");
        });
    }

    /// Access the connection through `f`, renewing the idle timer.
    ///
    /// Returns `None` if the connection has already been reclaimed.
    pub async fn access<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Connection) -> R,
    {
        let lock = self.inner.lock().await;
        lock.as_ref().map(|conn| {
            self.notify.notify_one(); // renew
            f(conn)
        })
    }

    /// The peer address, renewing the idle timer if the connection is alive.
    pub async fn addr(&self) -> Option<SocketAddr> {
        self.access(|conn| conn.addr).await
    }

    /// The socket for this connection, renewing the idle timer if alive.
    pub async fn socket(&self) -> Option<Arc<UdpSocket>> {
        self.access(|conn| Arc::clone(&conn.socket)).await
    }

    /// Whether the connection is still held (not yet reclaimed).
    pub async fn is_alive(&self) -> bool {
        self.inner.lock().await.is_some()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080))
    }

    async fn socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    #[tokio::test]
    async fn expires_when_idle() {
        let guard = IdleConnectionGuard::new(addr(), socket().await, Duration::from_millis(50));
        assert!(guard.is_alive().await);

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(!guard.is_alive().await);
        assert_eq!(guard.addr().await, None);
    }

    #[tokio::test]
    async fn access_renews_ttl() {
        let guard = IdleConnectionGuard::new(addr(), socket().await, Duration::from_millis(80));

        // Keep accessing within the window; the connection must survive past one ttl.
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            assert_eq!(guard.addr().await, Some(addr()));
        }

        assert!(guard.is_alive().await);
    }

    #[tokio::test]
    async fn keepalive_sends_then_stops() {
        // A peer socket that receives the keepalive Ping packets.
        let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_addr = peer.local_addr().unwrap();
        let local = socket().await;

        let guard = IdleConnectionGuard::new(peer_addr, local, Duration::from_millis(120));

        // At least one keepalive should arrive while the connection is alive.
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut buf))
            .await
            .expect("expected a keepalive packet")
            .unwrap();
        let header = PacketHeader::from_bytes(&buf[..n]).expect("valid header");
        assert_eq!(header.packet_type, NoeioPacketType::Ping);

        // After the connection expires, keepalive must stop: no more packets.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!guard.is_alive().await);
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), peer.recv(&mut buf))
                .await
                .is_err(),
            "keepalive should have stopped after ttl"
        );
    }
}
