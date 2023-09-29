#![forbid(unsafe_code)]

//! Event and General sockets for linux systems

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use statime::Time;
use timestamped_socket::{
    interface::InterfaceName,
    socket::{open_interface_udp4, open_interface_udp6, InterfaceTimestampMode, Open, Socket},
};

const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x0e, 0, 0, 0, 0, 0x01, 0x81);
const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x02, 0, 0, 0, 0, 0, 0x6b);

const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

const EVENT_PORT: u16 = 319;
const GENERAL_PORT: u16 = 320;

pub trait PtpTargetAddress {
    const PRIMARY_EVENT: Self;
    const PRIMARY_GENERAL: Self;
    const PDELAY_EVENT: Self;
    const PDELAY_GENERAL: Self;
}

impl PtpTargetAddress for SocketAddrV4 {
    const PRIMARY_EVENT: Self = SocketAddrV4::new(IPV4_PRIMARY_MULTICAST, EVENT_PORT);
    const PRIMARY_GENERAL: Self = SocketAddrV4::new(IPV4_PRIMARY_MULTICAST, GENERAL_PORT);
    const PDELAY_EVENT: Self = SocketAddrV4::new(IPV4_PDELAY_MULTICAST, EVENT_PORT);
    const PDELAY_GENERAL: Self = SocketAddrV4::new(IPV4_PDELAY_MULTICAST, GENERAL_PORT);
}

impl PtpTargetAddress for SocketAddrV6 {
    const PRIMARY_EVENT: Self = SocketAddrV6::new(IPV6_PRIMARY_MULTICAST, EVENT_PORT, 0, 0);
    const PRIMARY_GENERAL: Self = SocketAddrV6::new(IPV6_PRIMARY_MULTICAST, GENERAL_PORT, 0, 0);
    const PDELAY_EVENT: Self = SocketAddrV6::new(IPV6_PDELAY_MULTICAST, EVENT_PORT, 0, 0);
    const PDELAY_GENERAL: Self = SocketAddrV6::new(IPV6_PDELAY_MULTICAST, GENERAL_PORT, 0, 0);
}

pub fn open_ipv4_event_socket(
    interface: InterfaceName,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    let socket = open_interface_udp4(interface, EVENT_PORT, timestamping)?;
    socket.join_multicast(SocketAddrV4::new(IPV4_PRIMARY_MULTICAST, 0), interface)?;
    socket.join_multicast(SocketAddrV4::new(IPV4_PDELAY_MULTICAST, 0), interface)?;
    Ok(socket)
}

pub fn open_ipv4_general_socket(
    interface: InterfaceName,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    let socket = open_interface_udp4(interface, GENERAL_PORT, InterfaceTimestampMode::None)?;
    socket.join_multicast(SocketAddrV4::new(IPV4_PRIMARY_MULTICAST, 0), interface)?;
    socket.join_multicast(SocketAddrV4::new(IPV4_PDELAY_MULTICAST, 0), interface)?;
    Ok(socket)
}

pub fn open_ipv6_event_socket(
    interface: InterfaceName,
    timestamping: InterfaceTimestampMode,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    let socket = open_interface_udp6(interface, EVENT_PORT, timestamping)?;
    socket.join_multicast(
        SocketAddrV6::new(IPV6_PRIMARY_MULTICAST, 0, 0, 0),
        interface,
    )?;
    socket.join_multicast(SocketAddrV6::new(IPV6_PDELAY_MULTICAST, 0, 0, 0), interface)?;
    Ok(socket)
}

pub fn open_ipv6_general_socket(
    interface: InterfaceName,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    let socket = open_interface_udp6(interface, GENERAL_PORT, InterfaceTimestampMode::None)?;
    // Port, flowinfo and scope doesn't matter for join multicast
    socket.join_multicast(
        SocketAddrV6::new(IPV6_PRIMARY_MULTICAST, 0, 0, 0),
        interface,
    )?;
    socket.join_multicast(SocketAddrV6::new(IPV6_PDELAY_MULTICAST, 0, 0, 0), interface)?;
    Ok(socket)
}

pub fn timestamp_to_time(ts: timestamped_socket::socket::Timestamp) -> Time {
    Time::from_fixed_nanos(ts.seconds as i128 * 1_000_000_000i128 + ts.nanos as i128)
}
