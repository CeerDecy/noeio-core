use crate::pkg::command::run_command;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use smoltcp::phy::PcapLinkType::Ip;
use tun::{AbstractDevice, DeviceReader, DeviceWriter, Layer, ToAddress};

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
    pub ip: IpAddr,
}

impl VirtualNic {
    pub async fn create_ipv4_nic(ip: Ipv4Addr) -> (VirtualNic, DeviceReader) {
        let device = Self::create_tun().unwrap();

        let tun_name = device.tun_name().unwrap();

        // set host ip
        run_command(format!("ifconfig {} {:?}/{} {:?} up", tun_name, ip, "32", ip).as_str())
            .await
            .unwrap();

        let (tun_writer, tun_reader) = device.split().unwrap();

        (VirtualNic {
            writer: tun_writer,
            tun_name,
            ip: IpAddr::V4(ip),
        }, tun_reader)
    }

    pub async fn add_router_rule(
        &self,
        target: IpAddr,
        netmask: &str,
        hopcount: &str,
    ) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "macos")]
        let cmd = format!(
            "route -n add {} -netmask {} -interface {} -hopcount {}",
            target, netmask, self.tun_name, hopcount
        );

        #[cfg(target_os = "linux")]
        let cmd = {
            let prefix = netmask_to_prefix(netmask)?;
            format!(
                "ip route add {}/{} dev {} metric {}",
                target, prefix, self.tun_name, hopcount
            )
        };

        #[cfg(target_os = "windows")]
        let cmd = {
            let prefix = netmask_to_prefix(netmask)?;
            format!(
                "netsh interface ipv4 add route prefix={}/{} interface=\"{}\" metric={}",
                target, prefix, self.tun_name, hopcount
            )
        };

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let cmd: String = {
            let _ = (target, netmask, hopcount);
            return Err("add_router_rule: unsupported platform".into());
        };

        run_command(&cmd).await
    }

    fn create_tun() -> Result<tun::AsyncDevice, Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config.layer(Layer::L3);
        config.mtu(NIC_MTU);

        // macOS kernel requires utun interface names to be `utunN`, so a
        // custom name can only be set on other platforms.
        #[cfg(not(target_os = "macos"))]
        config.tun_name("noeio0");

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            config.packet_information(false);
        });

        config.up();

        Ok(tun::create_as_async(&config)?)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn netmask_to_prefix(netmask: &str) -> Result<u8, Box<dyn Error>> {
    let addr: Ipv4Addr = netmask
        .parse()
        .map_err(|_| format!("invalid netmask: {}", netmask))?;
    let bits = u32::from(addr);
    let ones = bits.leading_ones();
    let expected = if ones == 32 { u32::MAX } else { !0u32 << (32 - ones) };
    if bits != expected {
        return Err(format!("non-contiguous netmask: {}", netmask).into());
    }
    Ok(ones as u8)
}
