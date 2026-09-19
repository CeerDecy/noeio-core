use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use tun::{AbstractDevice, DeviceReader, DeviceWriter, Layer};

/// MTU of the virtual nic, sized so a full inner packet never fragments the
/// outer datagram on a 1500-byte physical path, even over IPv6:
///
/// `1500 - 40 (outer IPv6) - 8 (UDP) - 9 (noeio header) - 32 (WG data
/// overhead) = 1411`
///
/// (IPv4 outer leaves 20 bytes of slack; WireGuard's conventional 1420 minus
/// our 9-byte envelope gives the same number.)
pub const NIC_MTU: u16 = 1411;

pub struct VirtualNic {
    pub writer: DeviceWriter,
    pub tun_name: String,
    pub tun_index: u32,
    pub ip: IpAddr,
}

impl VirtualNic {
    pub async fn create_ipv4_nic(
        ip: Ipv4Addr,
    ) -> Result<(VirtualNic, DeviceReader), Box<dyn Error>> {
        let device = Self::create_tun(ip)?;
        let tun_name = device.tun_name()?;
        let tun_index = u32::try_from(device.tun_index()?)?;
        let (tun_writer, tun_reader) = device.split()?;

        Ok((
            VirtualNic {
                writer: tun_writer,
                tun_name,
                tun_index,
                ip: IpAddr::V4(ip),
            },
            tun_reader,
        ))
    }

    pub async fn add_router_rule(
        &self,
        target: IpAddr,
        netmask: &str,
        hopcount: &str,
    ) -> Result<(), Box<dyn Error>> {
        let metric = hopcount
            .parse::<u32>()
            .map_err(|_| format!("invalid route metric: {hopcount}"))?;
        noeio_net_route::add_route(target, netmask, self.tun_index, metric).await?;
        Ok(())
    }

    fn create_tun(ip: Ipv4Addr) -> Result<tun::AsyncDevice, Box<dyn Error>> {
        let mut config = tun::Configuration::default();
        config.layer(Layer::L3);
        config.mtu(NIC_MTU);
        config.up();

        // The crate applies these through the platform's own API — ioctl on
        // Unix, the wintun adapter API on Windows — so the image doesn't need
        // ifconfig or netsh. A /32 host mask reproduces the point-to-point
        // setup those commands used to install. configure() applies the
        // address before enabling the interface, matching `ifconfig A/32 A up`.
        config.address(ip);
        config.netmask(Ipv4Addr::new(255, 255, 255, 255));

        // On Unix `destination` is the point-to-point peer, which is ourselves.
        // On Windows the crate maps this field to the adapter's *default
        // gateway*, so setting it would point the host's default route at
        // noeio rather than leaving our per-peer split-tunnel routes as the
        // only ones we add.
        #[cfg(not(target_os = "windows"))]
        config.destination(ip);

        // macOS requires `utunN`, so a custom name can only be set elsewhere.
        #[cfg(not(target_os = "macos"))]
        config.tun_name("noeio0");

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            config.packet_information(false);
        });

        Ok(tun::create_as_async(&config)?)
    }
}
