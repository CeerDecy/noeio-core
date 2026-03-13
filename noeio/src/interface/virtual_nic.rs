use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::pkg::command::run_command;
use tun::{AbstractDevice, DeviceReader, DeviceWriter, Layer};

pub struct VirtualNic {
    pub tun: tun::AsyncDevice,
}

impl VirtualNic {
    pub async fn create() -> VirtualNic {
        let device = Self::create_tun().unwrap();

        let tun_name = device.tun_name().unwrap();

        run_command(
            format!(
                "ifconfig {} {:?}/{:?} 110.32.45.1 up",
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

        VirtualNic { tun: device }
    }

    fn create_tun() -> Result<tun::AsyncDevice, Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config.layer(Layer::L3);

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            config.packet_information(false);
        });

        config.up();

        Ok(tun::create_as_async(&config)?)
    }

    pub fn split(self) -> std::io::Result<(DeviceWriter, DeviceReader)> {
        self.tun.split()
    }
}