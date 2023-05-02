//! Implementation of the abstract network types for the linux platform

use std::{
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use statime::{
    clock::Clock,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
};
use tokio::io::{unix::AsyncFd, Interest};

use crate::{
    clock::LinuxClock,
    network::{
        interface::{InterfaceIterator, InterfaceName},
        raw_udp_socket::RawUdpSocket,
        timestamped_udp_socket::TimestampedUdpSocket,
    },
};

/// The time-critical port
const TC_PORT: u16 = 319;
/// The non-time-critical port
const NTC_PORT: u16 = 320;

#[derive(Debug, Clone, Copy)]
pub enum TimestampingMode {
    Hardware(InterfaceName),
    Software,
}

#[derive(Clone)]
pub struct LinuxRuntime {
    timestamping_mode: TimestampingMode,
    clock: LinuxClock,
}

impl LinuxRuntime {
    pub fn new(timestamping_mode: TimestampingMode, clock: LinuxClock) -> Self {
        LinuxRuntime {
            timestamping_mode,
            clock,
        }
    }

    const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x0e, 0, 0, 0, 0, 0x01, 0x81);
    const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x02, 0, 0, 0, 0, 0, 0x6b);

    const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
    const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

    fn join_multicast(
        interface: &LinuxInterfaceDescriptor,
        socket: &std::net::UdpSocket,
    ) -> Result<SocketAddr, NetworkError> {
        let port = socket.local_addr()?.port();

        match interface.get_address()? {
            IpAddr::V4(ip) => {
                // TODO: multicast ttl limit for ipv4

                socket.join_multicast_v4(&Self::IPV4_PRIMARY_MULTICAST, &ip)?;
                socket.join_multicast_v4(&Self::IPV4_PDELAY_MULTICAST, &ip)?;

                Ok((Self::IPV4_PRIMARY_MULTICAST, port).into())
            }
            IpAddr::V6(_ip) => {
                // TODO: multicast hops limit for ipv6

                // 0 indicates any interface, though it is likely this interface does not
                // support multicast
                let if_index = interface.get_index().unwrap_or(0);

                socket.join_multicast_v6(&Self::IPV6_PRIMARY_MULTICAST, if_index)?;
                socket.join_multicast_v6(&Self::IPV6_PDELAY_MULTICAST, if_index)?;

                Ok((Self::IPV6_PRIMARY_MULTICAST, port).into())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxInterfaceDescriptor {
    pub interface_name: Option<InterfaceName>,
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

    fn get_address(&self) -> Result<IpAddr, NetworkError> {
        if let Some(name) = self.interface_name {
            let interfaces =
                InterfaceIterator::new().map_err(|_| NetworkError::CannotIterateInterfaces)?;

            interfaces
                .filter(|i| name == i.name)
                .filter_map(|i| i.socket_addr)
                .map(|socket_addr| socket_addr.ip())
                .find(|ip| match self.mode {
                    LinuxNetworkMode::Ipv4 => ip.is_ipv4(),
                    LinuxNetworkMode::Ipv6 => ip.is_ipv6(),
                })
                .ok_or(NetworkError::InterfaceDoesNotExist)
        } else {
            Ok(self.mode.unspecified_ip_addr())
        }
    }
}

impl FromStr for LinuxInterfaceDescriptor {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut interfaces = match InterfaceIterator::new() {
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

                interfaces
                    .find(|data| data.has_ip_addr(addr))
                    .map(|data| LinuxInterfaceDescriptor {
                        interface_name: Some(data.name),
                        mode: LinuxNetworkMode::Ipv4,
                    })
                    .ok_or(NetworkError::InterfaceDoesNotExist)
            }
            Err(_) => {
                if interfaces.any(|if_data| if_data.name.as_str() == s) {
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

        let tc_socket = RawUdpSocket::new_into_std(tc_addr, interface.interface_name)?;
        let ntc_socket = RawUdpSocket::new_into_std(ntc_addr, interface.interface_name)?;

        let tc_address = Self::join_multicast(&interface, &tc_socket)?;
        let ntc_address = Self::join_multicast(&interface, &ntc_socket)?;

        let tc_socket = TimestampedUdpSocket::from_udp_socket(tc_socket, self.timestamping_mode)?;
        let ntc_socket = AsyncFd::new(ntc_socket)?;

        Ok(LinuxNetworkPort {
            tc_socket,
            ntc_socket,
            tc_address,
            ntc_address,
            clock: self.clock.clone(),
        })
    }
}

pub struct LinuxNetworkPort {
    tc_socket: TimestampedUdpSocket,
    ntc_socket: AsyncFd<std::net::UdpSocket>,
    tc_address: SocketAddr,
    ntc_address: SocketAddr,
    clock: LinuxClock,
}

impl NetworkPort for LinuxNetworkPort {
    type Error = std::io::Error;

    async fn send(&mut self, data: &[u8]) -> Result<(), <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send NTC");

        let sender = |inner: &std::net::UdpSocket| inner.send_to(data, self.ntc_address);
        self.ntc_socket.async_io(Interest::WRITABLE, sender).await?;

        Ok(())
    }

    async fn send_time_critical(
        &mut self,
        data: &[u8],
    ) -> Result<statime::time::Instant, <LinuxNetworkPort as NetworkPort>::Error> {
        log::trace!("Send TC");

        let opt_instant = self.tc_socket.send(data, self.tc_address).await?;

        // TODO get a backup send timestamp from somewhere (it must be the same clock
        // used for timestamps!)
        Ok(opt_instant.unwrap())
    }

    async fn recv(&mut self) -> Result<NetworkPacket, <LinuxNetworkPort as NetworkPort>::Error> {
        let time_critical_future = async {
            let timestamp = self.tc_socket.recv(&self.clock).await?;

            log::trace!("Recv TC");

            Ok(timestamp)
        };

        let non_time_critical_future = async {
            let mut buffer = [0; 2048];
            let (received_len, _) = self
                .ntc_socket
                .async_io(Interest::READABLE, |inner| inner.recv_from(&mut buffer))
                .await?;
            log::trace!("Recv NTC");

            let data_too_long = |_| io::Error::new(ErrorKind::InvalidData, "too long");
            let data = buffer[..received_len].try_into().map_err(data_too_long)?;

            Ok(NetworkPacket {
                data,
                timestamp: self.clock.now(),
            })
        };

        tokio::select! {
            packet = time_critical_future => { packet }
            packet = non_time_critical_future => { packet }
        }
    }
}

pub fn get_clock_id() -> Option<[u8; 8]> {
    let candidates = InterfaceIterator::new()
        .unwrap()
        .filter_map(|data| data.mac);

    for mac in candidates {
        // Ignore multicast and locally administered mac addresses
        if mac[0] & 0x3 == 0 && mac.iter().any(|x| *x != 0) {
            let f = |i| mac.get(i).copied().unwrap_or_default();
            return Some(std::array::from_fn(f));
        }
    }

    None
}

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_setup_ipv4() -> Result<(), Box<dyn std::error::Error>> {
        let port = 8000;

        let interface = LinuxInterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv4,
        };

        let addr = SocketAddr::new(interface.mode.unspecified_ip_addr(), port);

        let socket = RawUdpSocket::new_into_std(addr, interface.interface_name)?;
        let address = LinuxRuntime::join_multicast(&interface, &socket)?;

        assert_ne!(address.ip(), interface.mode.unspecified_ip_addr());
        assert_eq!(address.port(), port);

        Ok(())
    }

    #[tokio::test]
    #[ignore = "gives an `invalid argument` OS error"]
    async fn port_setup_ipv6() -> Result<(), Box<dyn std::error::Error>> {
        let port = 8001;

        let interface = LinuxInterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv6,
        };

        let addr = SocketAddr::new(interface.mode.unspecified_ip_addr(), port);

        let socket = RawUdpSocket::new_into_std(addr, interface.interface_name)?;
        let address = LinuxRuntime::join_multicast(&interface, &socket)?;

        assert_ne!(address.ip(), interface.mode.unspecified_ip_addr());
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
    async fn interface_index_invalid() -> std::io::Result<()> {
        let interface = LinuxInterfaceDescriptor {
            interface_name: Some(InterfaceName::INVALID),
            mode: LinuxNetworkMode::Ipv4,
        };

        assert!(interface.get_index().is_none());

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

    #[test]
    fn test_interface_from_str() {
        let interface = LinuxInterfaceDescriptor::from_str("0.0.0.0").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert!(interface.interface_name.is_none());

        let interface = LinuxInterfaceDescriptor::from_str("::").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv6));
        assert!(interface.interface_name.is_none());

        let interface = LinuxInterfaceDescriptor::from_str("lo").unwrap();

        assert!(matches!(interface.mode, LinuxNetworkMode::Ipv4));
        assert_eq!(interface.interface_name.unwrap(), InterfaceName::LOOPBACK);

        let error = LinuxInterfaceDescriptor::from_str("xxx").unwrap_err();

        assert!(matches!(error, NetworkError::InterfaceDoesNotExist));
    }
}
