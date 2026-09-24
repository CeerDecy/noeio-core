use std::{
    fs::File,
    io::{self, Read, Write},
    mem::{self, size_of},
    net::{IpAddr, Ipv4Addr},
    os::fd::FromRawFd,
    ptr,
};

#[repr(C)]
struct RouteMessage {
    header: libc::rt_msghdr,
    attrs: [u8; 128],
}

pub fn add_route(target: IpAddr, prefix: u8, ifindex: u32, metric: u32) -> io::Result<()> {
    let target = ipv4_target(target)?;
    let ifindex = ifindex_u16(ifindex)?;
    let mut message = new_message(libc::RTM_ADD, target, prefix, Some(ifindex))?;
    message.header.rtm_inits = libc::RTV_HOPCOUNT as u32;
    message.header.rtm_rmx.rmx_hopcount = metric;
    send(&message)
}

/// Delete the route to `target/prefix`. The kernel matches on destination and
/// netmask; `ifindex` is passed as the gateway so a route through another
/// interface is not touched when one is given.
pub fn del_route(target: IpAddr, prefix: u8, ifindex: Option<u32>) -> io::Result<()> {
    let target = ipv4_target(target)?;
    let ifindex = ifindex.map(ifindex_u16).transpose()?;
    let message = new_message(libc::RTM_DELETE, target, prefix, ifindex)?;
    send(&message)
}

fn ipv4_target(target: IpAddr) -> io::Result<Ipv4Addr> {
    match target {
        IpAddr::V4(target) => Ok(target),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS route helper currently supports IPv4 targets only",
        )),
    }
}

fn ifindex_u16(ifindex: u32) -> io::Result<u16> {
    u16::try_from(ifindex).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface index is too large for macOS: {ifindex}"),
        )
    })
}

fn new_message(
    rtm_type: libc::c_int,
    target: Ipv4Addr,
    prefix: u8,
    ifindex: Option<u16>,
) -> io::Result<RouteMessage> {
    let mut message = RouteMessage {
        // SAFETY: all-zero is a valid initial value for the C routing structs.
        header: unsafe { mem::zeroed() },
        attrs: [0; 128],
    };
    message.header.rtm_version = libc::RTM_VERSION as u8;
    message.header.rtm_type = rtm_type as u8;
    message.header.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
    message.header.rtm_addrs = libc::RTA_DST | libc::RTA_NETMASK;
    message.header.rtm_pid = unsafe { libc::getpid() };
    message.header.rtm_seq = 1;

    // Attribute order is fixed by the RTA_* bit order: DST, GATEWAY, NETMASK.
    let mut offset = 0;
    append_attr(&mut message.attrs, &mut offset, &ipv4_sockaddr(target));
    if let Some(ifindex) = ifindex {
        message.header.rtm_addrs |= libc::RTA_GATEWAY;
        append_attr(
            &mut message.attrs,
            &mut offset,
            &interface_sockaddr(ifindex),
        );
    }
    append_attr(
        &mut message.attrs,
        &mut offset,
        &ipv4_sockaddr(Ipv4Addr::from(prefix_to_mask(prefix))),
    );

    let message_len = size_of::<libc::rt_msghdr>() + offset;
    message.header.rtm_msglen = u16::try_from(message_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS route message is too large",
        )
    })?;
    Ok(message)
}

fn send(message: &RouteMessage) -> io::Result<()> {
    let message_len = usize::from(message.header.rtm_msglen);
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by socket and is owned by this File.
    let mut socket = unsafe { File::from_raw_fd(fd) };
    let bytes = unsafe {
        std::slice::from_raw_parts((message as *const RouteMessage).cast::<u8>(), message_len)
    };
    socket.write_all(bytes)?;

    let mut reply = [0u8; size_of::<RouteMessage>()];
    let read = socket.read(&mut reply)?;
    if read < size_of::<libc::rt_msghdr>() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "macOS route socket returned a short response",
        ));
    }
    // SAFETY: the length check above guarantees a complete routing header.
    let header = unsafe { ptr::read_unaligned(reply.as_ptr().cast::<libc::rt_msghdr>()) };
    if header.rtm_errno != 0 {
        return Err(io::Error::from_raw_os_error(header.rtm_errno));
    }
    Ok(())
}

fn append_attr<T>(attrs: &mut [u8], offset: &mut usize, attr: &T) {
    let bytes =
        unsafe { std::slice::from_raw_parts((attr as *const T).cast::<u8>(), size_of::<T>()) };
    attrs[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    *offset += bytes.len();
}

fn ipv4_sockaddr(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn interface_sockaddr(ifindex: u16) -> libc::sockaddr_dl {
    libc::sockaddr_dl {
        sdl_len: size_of::<libc::sockaddr_dl>() as u8,
        sdl_family: libc::AF_LINK as u8,
        sdl_index: ifindex,
        sdl_type: 0,
        sdl_nlen: 0,
        sdl_alen: 0,
        sdl_slen: 0,
        sdl_data: [0; 12],
    }
}

fn prefix_to_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        32 => u32::MAX,
        _ => u32::MAX << (32 - prefix),
    }
}
