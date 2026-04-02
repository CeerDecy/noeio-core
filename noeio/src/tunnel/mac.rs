use pnet::datalink::{self, MacAddr, NetworkInterface};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

pub fn get_egress_interface_mac() -> io::Result<MacAddr> {
    let interface = get_egress_interface()?;

    interface.mac.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {} does not expose a MAC address", interface.name),
        )
    })
}

pub fn get_egress_interface() -> io::Result<NetworkInterface> {
    let egress_ip = detect_egress_ip()?;

    datalink::interfaces()
        .into_iter()
        .find(|interface| interface_has_ip(interface, egress_ip))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no interface found for egress IP {egress_ip}"),
            )
        })
}

fn detect_egress_ip() -> io::Result<IpAddr> {
    try_detect_egress_ip(SocketAddr::from(([8, 8, 8, 8], 80)))
        .or_else(|_| try_detect_egress_ip(SocketAddr::from(([1, 1, 1, 1], 80))))
        .or_else(|_| {
            try_detect_egress_ip(SocketAddr::from((
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
                80,
            )))
        })
}

fn try_detect_egress_ip(target: SocketAddr) -> io::Result<IpAddr> {
    let bind_addr = match target {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(target)?;

    let local_ip = socket.local_addr()?.ip();
    if local_ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "egress IP is unspecified",
        ));
    }

    Ok(local_ip)
}

fn interface_has_ip(interface: &NetworkInterface, ip: IpAddr) -> bool {
    interface.ips.iter().any(|network| network.ip() == ip)
}

#[cfg(test)]
mod tests {
    use super::interface_has_ip;
    use pnet::datalink::NetworkInterface;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn matches_interface_by_ipv4() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: String::new(),
            index: 1,
            mac: None,
            ips: vec!["192.168.31.20/24".parse().unwrap()],
            flags: 0,
        };

        assert!(interface_has_ip(
            &interface,
            IpAddr::V4(Ipv4Addr::new(192, 168, 31, 20))
        ));
    }

    #[test]
    fn matches_interface_by_ipv6() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: String::new(),
            index: 1,
            mac: None,
            ips: vec!["2001:db8::10/64".parse().unwrap()],
            flags: 0,
        };

        assert!(interface_has_ip(
            &interface,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10))
        ));
    }

    #[test]
    fn does_not_match_other_ip() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: String::new(),
            index: 1,
            mac: None,
            ips: vec!["10.0.0.5/24".parse().unwrap()],
            flags: 0,
        };

        assert!(!interface_has_ip(
            &interface,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))
        ));
    }
}
