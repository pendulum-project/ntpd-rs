//! Implementation of the abstract network types for the linux platform

use crate::{
    clock::{timespec_into_instant, LinuxClock},
    network::linux_syscall::driver_enable_hardware_timestamping,
};
use nix::{
    cmsg_space,
    errno::Errno,
    ifaddrs::{getifaddrs, InterfaceAddress, InterfaceAddressIterator},
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

    async fn bind_socket(
        interface_name: Option<InterfaceName>,
        addr: SocketAddr,
    ) -> Result<UdpSocket, NetworkError> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;

        // We want to allow multiple listening sockets, as we bind to a specific interface later
        setsockopt(socket.as_raw_fd(), ReuseAddr, &true).map_err(|_| NetworkError::UnknownError)?;

        // Bind device to specified interface
        if let Some(interface_name) = interface_name.as_ref() {
            let name = interface_name.as_str().as_bytes();

            // empty string does not work, `bind_device` should be skipped instead
            debug_assert!(!name.is_empty());

            socket.bind_device(Some(name))?;
        }

        Ok(socket)
    }

    fn join_multicast(
        interface: &LinuxInterfaceDescriptor,
        socket: &UdpSocket,
    ) -> Result<SocketAddr, NetworkError> {
        // TODO: multicast ttl limit for ipv4/multicast hops limit for ipv6

        let local_addr = socket.local_addr()?;

        match interface.get_address()? {
            IpAddr::V4(ip) => {
                socket.join_multicast_v4(Self::IPV4_PRIMARY_MULTICAST, ip)?;
                socket.join_multicast_v4(Self::IPV4_PDELAY_MULTICAST, ip)?;

                Ok((Self::IPV4_PRIMARY_MULTICAST, local_addr.port()).into())
            }
            IpAddr::V6(_ip) => {
                let if_index = interface.get_index().unwrap_or(0);

                socket.join_multicast_v6(&Self::IPV6_PRIMARY_MULTICAST, if_index)?;
                socket.join_multicast_v6(&Self::IPV6_PDELAY_MULTICAST, if_index)?;

                Ok((Self::IPV6_PRIMARY_MULTICAST, local_addr.port()).into())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor {
    interface_name: Option<InterfaceName>,
    mode: LinuxNetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxNetworkMode {
    Ipv4,
    Ipv6,
}

impl LinuxNetworkMode {
    fn unspecified_ip_addr(&self) -> IpAddr {
        match self {
            LinuxNetworkMode::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            LinuxNetworkMode::Ipv6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        }
    }
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

    pub const LOOPBACK: Self = Self {
        bytes: *b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.bytes.as_slice())
            .unwrap_or_default()
            .trim_end_matches('\0')
    }

    fn as_cstr(&self) -> &std::ffi::CStr {
        // it is an invariant of InterfaceName that the bytes are null-terminated
        std::ffi::CStr::from_bytes_until_nul(&self.bytes[..]).unwrap()
    }

    pub(crate) fn to_ifr_name(self) -> [i8; libc::IFNAMSIZ] {
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

        // >= so that we always retain a NUL byte at the end
        if s.len() >= bytes.len() {
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
        let name = self.interface_name.as_ref()?;

        // # SAFETY
        //
        // The pointer is valid and null-terminated
        match unsafe { libc::if_nametoindex(name.as_cstr().as_ptr()) } {
            0 => None,
            n => Some(n),
        }
    }

    fn convert_sockaddr_storage(mode: LinuxNetworkMode, i: InterfaceAddress) -> Option<IpAddr> {
        match mode {
            LinuxNetworkMode::Ipv4 => {
                let a: Option<u32> = i.address?.as_sockaddr_in()?.ip().into();
                Some(IpAddr::from(Ipv4Addr::from(a?)))
            }
            LinuxNetworkMode::Ipv6 => {
                let a: Option<_> = i.address?.as_sockaddr_in6()?.ip().into();
                Some(IpAddr::from(a?))
            }
        }
    }

    fn get_address(&self) -> Result<IpAddr, NetworkError> {
        if let Some(ref name) = self.interface_name {
            let interfaces = getifaddrs().map_err(|_| NetworkError::CannotIterateInterfaces)?;

            interfaces
                .filter(|i| name.as_str() == i.interface_name)
                .find_map(|i| Self::convert_sockaddr_storage(self.mode, i))
                .ok_or(NetworkError::InterfaceDoesNotExist)
        } else {
            Ok(self.mode.unspecified_ip_addr())
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
                        mode: match addr {
                            IpAddr::V4(_) => LinuxNetworkMode::Ipv4,
                            IpAddr::V6(_) => LinuxNetworkMode::Ipv6,
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

        let bind_ip = interface.mode.unspecified_ip_addr();
        let tc_addr = SocketAddr::new(bind_ip, TC_PORT);
        let ntc_addr = SocketAddr::new(bind_ip, NTC_PORT);

        log::info!("Binding time critical socket on {tc_addr}");
        log::info!("Binding non time critical socket on {ntc_addr}");

        let tc_socket = Self::bind_socket(interface.interface_name, tc_addr).await?;
        let ntc_socket = Self::bind_socket(interface.interface_name, ntc_addr).await?;

        let tc_address = Self::join_multicast(&interface, &tc_socket)?;
        let ntc_address = Self::join_multicast(&interface, &ntc_socket)?;

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

    #[tokio::test]
    async fn port_setup() -> Result<(), Box<dyn std::error::Error>> {
        let port = 8000;

        let interface = LinuxInterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv4,
        };

        let bind_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let addr = SocketAddr::new(bind_ip, port);

        let socket = LinuxRuntime::bind_socket(interface.interface_name, addr).await?;
        let address = LinuxRuntime::join_multicast(&interface, &socket)?;

        assert_ne!(address.ip(), bind_ip);
        assert_eq!(address.port(), port);

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_ipv4() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn interface_index_ipv6() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert!(interface.get_index().is_some());

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv4_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert_eq!(interface.get_address()?, Ipv4Addr::LOCALHOST);

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv6_valid() -> Result<(), Box<dyn std::error::Error>> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::LOOPBACK),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert_eq!(interface.get_address()?, Ipv6Addr::LOCALHOST);

        Ok(())
    }

    #[tokio::test]
    async fn get_address_ipv4_invalid() {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(matches!(
            interface.get_address().unwrap_err(),
            NetworkError::InterfaceDoesNotExist
        ));
    }

    #[tokio::test]
    async fn get_address_ipv6_invalid() {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::from_str("invalid").unwrap()),
            mode: LinuxNetworkMode::Ipv6,
        };

        assert!(matches!(
            interface.get_address().unwrap_err(),
            NetworkError::InterfaceDoesNotExist
        ));
    }
}
