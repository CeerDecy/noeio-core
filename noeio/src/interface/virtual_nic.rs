use std::io::Read;
use std::sync::Arc;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use tokio::sync::Mutex;
use crate::pkg::command::run_command;
use tokio::time;
use tun::{AbstractDevice, Layer};

pub struct VirtualNic {
    pub tun: Arc<Mutex<tun::Device>>,
}

impl VirtualNic {
    pub async fn new() -> VirtualNic {
        let mut device = Self::create_tun().unwrap();

        let tun_name = device.tun_name().unwrap();

        run_command(
            format!(
                "ifconfig {} {:?}/{:?} 11.32.45.1 up",
                tun_name, "110.32.45.1", "32"
            )
            .as_str(),
        )
        .await
        .unwrap();

        run_command(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount {}",
                "110.0.0.1", "255.255.255.255", tun_name, "7"
            )
            .as_str(),
        )
        .await
        .unwrap();

        VirtualNic { tun: Arc::new(Mutex::new(device)) }
    }

    pub fn create_tun() -> Result<tun::Device, Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config.layer(Layer::L3);

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            config.packet_information(false);
        });

        config.up();

        Ok(tun::create(&config)?)
    }
}
