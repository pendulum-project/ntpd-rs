//! Implementation of the abstract network types for the linux platform

use crate::{
    clock::{timespec_into_instant, LinuxClock},
    network::linux_syscall::driver_enable_hardware_timestamping,
};
use nix::{
    cmsg_space,
    errno::Errno,
    ifaddrs::{getifaddrs, InterfaceAddress, InterfaceAddressIterator},
    net::if_::if_nametoindex,
    sys::socket::{
        recvmsg, setsockopt,
        sockopt::{ReuseAddr, Timestamping},
        ControlMessageOwned, MsgFlags, SockaddrStorage, TimestampingFlag, Timestamps,
    },
};
use statime::{
    clock::Clock,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
    time::Instant,
};
use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    str::FromStr,
};
use tokio::{io::Interest, net::UdpSocket};

/// The time-critical port
const TC_PORT: u16 = 319;
/// The non-time-critical port
const NTC_PORT: u16 = 320;

#[derive(Clone)]
pub struct LinuxRuntime {
    hardware_timestamping: bool,
    clock: LinuxClock,
}

impl LinuxRuntime {
    pub fn new(hardware_timestamping: bool, clock: &LinuxClock) -> Self {
        LinuxRuntime {
            hardware_timestamping,
            clock: clock.clone(),
        }
    }

    const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xFF, 0x0E, 0, 0, 0, 0, 0x01, 0x81);
    const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0, 0x6B);

    const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
    const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor {
    interface_name: Option<InterfaceName>,
    mode: LinuxNetworkMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxNetworkMode {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterfaceName {
    bytes: [u8; libc::IFNAMSIZ],
}

impl core::ops::Deref for InterfaceName {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes.as_slice()
    }
}

impl InterfaceName {
    pub const DEFAULT: Option<Self> = None;

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.as_slice())
            .unwrap_or_default()
            .trim_end_matches('\0')
    }

    pub(crate) fn to_ifr_name(&self) -> [i8; libc::IFNAMSIZ] {
        let mut it = self.bytes.iter().copied();
        [0; libc::IFNAMSIZ].map(|_| it.next().unwrap_or(0) as i8)
    }
}

impl std::fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InterfaceName")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for InterfaceName {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0; libc::IFNAMSIZ];

        if s.len() > bytes.len() {
            return Err(());
        }

        if s.is_empty() {
            // this causes problems down the line when giving the interface name to tokio
            return Err(());
        }

        let mut it = s.bytes();
        bytes = bytes.map(|_| it.next().unwrap_or_default());

        Ok(Self { bytes })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("Unknown error")]
    UnknownError,
    #[error("Not allowed to bind to port {0}")]
    NoBindPermission(u16),
    #[error("Socket bind port {0} already in use")]
    AddressInUse(u16),
    #[error("Could not bind socket to a specific device")]
    BindToDeviceFailed,
    #[error("Could not iterate over interfaces")]
    CannotIterateInterfaces,
    #[error("The specified interface does not exist")]
    InterfaceDoesNotExist,
    #[error("No more packets")]
    NoMorePackets,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl LinuxInterfaceDescriptor {
    fn get_index(&self) -> Option<u32> {
        if let Some(ref name) = self.interface_name {
            if_nametoindex(&name[..]).ok()
        } else {
            None
        }
    }

    fn get_address(&self) -> Result<IpAddr, NetworkError> {
        if let Some(ref name) = self.interface_name {
            let interfaces = match getifaddrs() {
                Ok(a) => a,
                Err(_) => return Err(NetworkError::CannotIterateInterfaces),
            };
            for i in interfaces {
                if name.as_str() == i.interface_name {
                    if self.mode == LinuxNetworkMode::Ipv6 {
                        if let Some(ip) = i
                            .address
                            .and_then(|a| a.as_sockaddr_in6().map(|a| a.ip().into()))
                            .flatten()
                        {
                            return Ok(ip.into());
                        }
                    } else if let Some(ip) = i
                        .address
                        .and_then(|a| a.as_sockaddr_in().map(|a| a.ip().into()))
                        .flatten()
                    {
                        return Ok(Ipv4Addr::from(ip).into());
                    }
                }
            }
            Err(NetworkError::InterfaceDoesNotExist)
        } else if self.mode == LinuxNetworkMode::Ipv6 {
            Ok(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
        } else {
            Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
    }
}

impl FromStr for LinuxInterfaceDescriptor {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let interfaces = match getifaddrs() {
            Ok(a) => a,
            Err(_) => return Err(NetworkError::CannotIterateInterfaces),
        };

        match std::net::IpAddr::from_str(s) {
            Ok(addr) => {
                if addr.is_unspecified() {
                    return Ok(LinuxInterfaceDescriptor {
                        interface_name: None,
                        mode: if addr.is_ipv4() {
                            LinuxNetworkMode::Ipv4
                        } else {
                            LinuxNetworkMode::Ipv6
                        },
                    });
                }

                let sock_addr = std::net::SocketAddr::new(addr, 0);
                for ifaddr in interfaces {
                    if if_has_address(&ifaddr, sock_addr.ip()) {
                        // the interface name came straight from the OS, so it must be valid
                        let interface_name =
                            InterfaceName::from_str(&ifaddr.interface_name).unwrap();

                        return Ok(LinuxInterfaceDescriptor {
                            interface_name: Some(interface_name),
                            mode: LinuxNetworkMode::Ipv4,
                        });
                    }
                }

                Err(NetworkError::InterfaceDoesNotExist)
            }
            Err(_) => {
                if if_name_exists(interfaces, s) {
                    // the interface name came straight from the OS, so it must be valid
                    let interface_name = InterfaceName::from_str(s).unwrap();

                    Ok(LinuxInterfaceDescriptor {
                        interface_name: Some(interface_name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                } else {
                    Err(NetworkError::InterfaceDoesNotExist)
                }
            }
        }
    }
}

fn if_has_address(ifaddr: &InterfaceAddress, address: IpAddr) -> bool {
    match address {
        IpAddr::V4(addr1) => match ifaddr.address.and_then(|a| a.as_sockaddr_in().copied()) {
            None => false,
            Some(addr2) => addr1.octets() == addr2.ip().to_be_bytes(),
        },
        IpAddr::V6(addr1) => match ifaddr.address.and_then(|a| a.as_sockaddr_in6().copied()) {
            None => false,
            Some(addr2) => addr1.octets() == addr2.ip().octets(),
        },
    }
}

fn if_name_exists(interfaces: InterfaceAddressIterator, name: &str) -> bool {
    interfaces.into_iter().any(|i| i.interface_name == name)
}

impl NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = LinuxInterfaceDescriptor;
    type NetworkPort = LinuxNetworkPort;
    type Error = NetworkError;

    async fn open(
        &mut self,
        interface: Self::InterfaceDescriptor,
    ) -> Result<<LinuxRuntime as NetworkRuntime>::NetworkPort, NetworkError> {
        log::info!(
            "Opening network port on '{}'",
            interface
                .interface_name
                .as_ref()
                .map(|if_name| if_name.as_str())
                .unwrap_or("Unknown")
        );

        let bind_ip = match interface.mode {
            LinuxNetworkMode::Ipv6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            LinuxNetworkMode::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let tc_addr = SocketAddr::new(bind_ip, TC_PORT);
        let ntc_addr = SocketAddr::new(bind_ip, NTC_PORT);

        log::info!("Binding time critical socket on {tc_addr}");
        log::info!("Binding non time critical socket on {ntc_addr}");

        let tc_socket = tokio::net::UdpSocket::bind(tc_addr).await?;
        // We want to allow multiple listening sockets, as we bind to a specific interface later
        setsockopt(tc_socket.as_raw_fd(), ReuseAddr, &true)
            .map_err(|_| NetworkError::UnknownError)?;
        let ntc_socket = tokio::net::UdpSocket::bind(ntc_addr).await?;
        // We want to allow multiple listening sockets, as we bind to a specific interface later
        setsockopt(ntc_socket.as_raw_fd(), ReuseAddr, &true)
            .map_err(|_| NetworkError::UnknownError)?;

        // Bind device to specified interface
        let interface_name = interface.interface_name.as_ref().map(|string| {
            // empty string does not work well with tokio. `None`should be used instead
            debug_assert!(!string.as_str().is_empty());
            string.as_str().as_bytes()
        });

        tc_socket.bind_device(interface_name)?;
        ntc_socket.bind_device(interface_name)?;

        // TODO: multicast ttl limit for ipv4/multicast hops limit for ipv6

        let (tc_address, ntc_address) = match interface.get_address()? {
            IpAddr::V4(ip) => {
                tc_socket.join_multicast_v4(Self::IPV4_PRIMARY_MULTICAST, ip)?;
                ntc_socket.join_multicast_v4(Self::IPV4_PRIMARY_MULTICAST, ip)?;
                tc_socket.join_multicast_v4(Self::IPV4_PDELAY_MULTICAST, ip)?;
                ntc_socket.join_multicast_v4(Self::IPV4_PDELAY_MULTICAST, ip)?;

                (
                    (Self::IPV4_PRIMARY_MULTICAST, TC_PORT).into(),
                    (Self::IPV4_PRIMARY_MULTICAST, NTC_PORT).into(),
                )
            }
            IpAddr::V6(_ip) => {
                let if_index = interface.get_index().unwrap_or(0);

                tc_socket.join_multicast_v6(&Self::IPV6_PRIMARY_MULTICAST, if_index)?;
                ntc_socket.join_multicast_v6(&Self::IPV6_PRIMARY_MULTICAST, if_index)?;
                tc_socket.join_multicast_v6(&Self::IPV6_PDELAY_MULTICAST, if_index)?;
                ntc_socket.join_multicast_v6(&Self::IPV6_PDELAY_MULTICAST, if_index)?;

                (
                    (Self::IPV6_PRIMARY_MULTICAST, TC_PORT).into(),
                    (Self::IPV6_PRIMARY_MULTICAST, NTC_PORT).into(),
                )
            }
        };

        // Setup timestamping
        let timestamping_flags = if self.hardware_timestamping {
            // the interface name is only required when using hardware timestamping
            let interface_name = interface
                .interface_name
                .ok_or(NetworkError::InterfaceDoesNotExist)?;

            // must explicitly enable hardware timestamping
            driver_enable_hardware_timestamping(tc_socket.as_raw_fd(), interface_name);

            TimestampingFlag::SOF_TIMESTAMPING_RAW_HARDWARE
                | TimestampingFlag::SOF_TIMESTAMPING_RX_HARDWARE
                | TimestampingFlag::SOF_TIMESTAMPING_TX_HARDWARE
        } else {
            TimestampingFlag::SOF_TIMESTAMPING_SOFTWARE
                | TimestampingFlag::SOF_TIMESTAMPING_RX_SOFTWARE
                | TimestampingFlag::SOF_TIMESTAMPING_TX_SOFTWARE
        };

        setsockopt(tc_socket.as_raw_fd(), Timestamping, &timestamping_flags)
            .map_err(|_| NetworkError::UnknownError)?;

        Ok(LinuxNetworkPort {
            tc_socket,
            ntc_socket,
            tc_address,
            ntc_address,
            hardware_timestamping: self.hardware_timestamping,
            clock: self.clock.clone(),
        })
    }
}

pub struct LinuxNetworkPort {
    tc_socket: UdpSocket,
    ntc_socket: UdpSocket,
    tc_address: SocketAddr,
    ntc_address: SocketAddr,
    hardware_timestamping: bool,
    clock: LinuxClock,
}

impl NetworkPort for LinuxNetworkPort {
    type Error = std::io::Error;

    async fn send(&mut self, data: &[u8]) -> Result<(), <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send NTC");

        self.ntc_socket.send_to(data, self.ntc_address).await?;
        Ok(())
    }

    async fn send_time_critical(
        &mut self,
        data: &[u8],
    ) -> Result<statime::time::Instant, <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send TC");

        self.tc_socket.send_to(data, self.tc_address).await?;

        loop {
            self.tc_socket.readable().await?;

            if let Some(ts) =
                Self::try_recv_tx_timestamp(&mut self.tc_socket, self.hardware_timestamping)?
            {
                return Ok(ts);
            }
        }
    }

    async fn recv(&mut self) -> Result<NetworkPacket, <LinuxNetworkPort as NetworkPort>::Error> {
        let clock = &self.clock;
        let time_critical_future = async {
            loop {
                self.tc_socket.readable().await?;
                match self.tc_socket.try_io(Interest::READABLE, || {
                    Self::try_recv_message_with_timestamp(
                        &self.tc_socket,
                        &self.clock,
                        self.hardware_timestamping,
                    )
                }) {
                    Ok(packet) => {
                        log::trace!("Recv TC");
                        break Ok(packet);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(e),
                }
            }
        };
        let non_time_critical_future = async {
            let mut buffer = [0; 2048];
            let (received_len, _) = self.ntc_socket.recv_from(&mut buffer).await?;
            log::trace!("Recv NTC");
            Ok(NetworkPacket {
                data: buffer[..received_len]
                    .try_into()
                    .map_err(|_| io::Error::new(ErrorKind::InvalidData, "too long"))?,
                timestamp: clock.now(),
            })
        };

        tokio::select! {
            packet = time_critical_future => { packet }
            packet = non_time_critical_future => { packet }
        }
    }
}

impl LinuxNetworkPort {
    /// Do a manual receive on the time critical socket so we can get the hardware timestamps.
    /// Tokio doesn't have the capability to get the timestamp.
    ///
    /// This returns an option because there may not be a message
    fn try_recv_message_with_timestamp(
        tc_socket: &UdpSocket,
        clock: &LinuxClock,
        hardware_timestamping: bool,
    ) -> Result<NetworkPacket, std::io::Error> {
        let mut read_buf = [0u8; 2048];
        let mut io_vec = [IoSliceMut::new(&mut read_buf)];
        let mut cmsg = cmsg_space!(Timestamps);

        // Tokio should have put the socket into non-blocking
        let received = match recvmsg::<SockaddrStorage>(
            tc_socket.as_raw_fd(),
            &mut io_vec,
            Some(&mut cmsg),
            MsgFlags::empty(),
        ) {
            Ok(received) => received,
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
        };

        let timestamp = received
            .cmsgs()
            .find_map(|cmsg| match cmsg {
                ControlMessageOwned::ScmTimestampsns(timestamps) => Some(timestamps),
                _ => None,
            })
            .map(|timestamps| {
                if hardware_timestamping {
                    timespec_into_instant(timestamps.hw_raw)
                } else {
                    timespec_into_instant(timestamps.system)
                }
            })
            .unwrap_or_else(|| clock.now());

        let received_len = received.bytes;

        Ok(NetworkPacket {
            data: read_buf[..received_len]
                .try_into()
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "too long"))?,
            timestamp,
        })
    }

    fn try_recv_tx_timestamp(
        tc_socket: &mut UdpSocket,
        hardware_timestamping: bool,
    ) -> Result<Option<Instant>, std::io::Error> {
        // We're not interested in the data, so we create an empty buffer
        let mut read_buf = [0u8; 0];
        let mut io_vec = [IoSliceMut::new(&mut read_buf)];
        let mut cmsg = cmsg_space!(Timestamps);

        let received = match recvmsg::<SockaddrStorage>(
            tc_socket.as_raw_fd(),
            &mut io_vec,
            Some(&mut cmsg),
            MsgFlags::MSG_ERRQUEUE, // We read from the error queue because that is where the tx timestamps are routed to
        ) {
            Ok(received) => received,
            Err(Errno::EWOULDBLOCK) => return Ok(None),
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
        };

        Ok(received
            .cmsgs()
            .find_map(|cmsg| match cmsg {
                ControlMessageOwned::ScmTimestampsns(timestamps) => Some(timestamps),
                _ => None,
            })
            .map(|timestamps| {
                if hardware_timestamping {
                    timespec_into_instant(timestamps.hw_raw)
                } else {
                    timespec_into_instant(timestamps.system)
                }
            }))
    }
}

pub fn get_clock_id() -> Option<[u8; 8]> {
    let candidates = getifaddrs().unwrap();
    for candidate in candidates {
        if let Some(mac) = candidate
            .address
            .and_then(|addr| addr.as_link_addr().map(|mac| mac.addr()))
            .flatten()
        {
            // Ignore multicast and locally administered mac addresses
            if mac[0] & 0x3 == 0 && mac.iter().any(|x| *x != 0) {
                let mut result: [u8; 8] = [0; 8];
                for (i, v) in mac.iter().enumerate() {
                    result[i] = *v;
                }
                return Some(result);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_from_string() {
        assert!(InterfaceName::from_str("").is_err());
        assert!(InterfaceName::from_str("a string that is too long").is_err());

        let input = "enp0s31f6";
        assert_eq!(InterfaceName::from_str(input).unwrap().as_str(), input);

        let ifr_name = (*b"enp0s31f6\0\0\0\0\0\0\0").map(|b| b as i8);
        assert_eq!(
            InterfaceName::from_str(input).unwrap().to_ifr_name(),
            ifr_name
        );
    }
}
