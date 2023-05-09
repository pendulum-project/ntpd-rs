#![forbid(unsafe_code)]

//! Implementation of the abstract network types for the linux platform

use std::{
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use statime::{
    clock::Clock,
    datastructures::messages::MAX_DATA_LEN,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
    time::Instant,
};
use tokio::io::{unix::AsyncFd, Interest};

pub use super::interface::InterfaceDescriptor;
use crate::{
    clock::LinuxClock,
    network::{
        interface::{InterfaceIterator, InterfaceName},
        raw_udp_socket::RawUdpSocket,
        timestamped_udp_socket::{LibcTimestamp, TimestampedUdpSocket},
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
        interface: &InterfaceDescriptor,
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

impl NetworkRuntime for LinuxRuntime {
    type InterfaceDescriptor = InterfaceDescriptor;
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

fn libc_timestamp_to_instant(ts: LibcTimestamp) -> Instant {
    match ts {
        LibcTimestamp::TimeSpec { seconds, nanos } => {
            Instant::from_fixed_nanos(seconds as i128 * 1_000_000_000i128 + nanos as i128)
        }
        LibcTimestamp::TimeVal { seconds, micros } => {
            Instant::from_fixed_nanos(seconds as i128 * 1_000_000_000i128 + micros as i128 * 1_000)
        }
    }
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
    ) -> Result<Option<statime::time::Instant>, std::io::Error> {
        log::trace!("Send TC");

        let opt_libc_ts = self.tc_socket.send(data, self.tc_address).await?;

        Ok(opt_libc_ts.map(libc_timestamp_to_instant))
    }

    async fn recv(&mut self) -> Result<NetworkPacket, <LinuxNetworkPort as NetworkPort>::Error> {
        let time_critical_future = async {
            let mut buf = [0; MAX_DATA_LEN];

            let recv_result = self.tc_socket.recv(&self.clock, &mut buf).await?;

            let packet = NetworkPacket {
                data: buf.into(),
                timestamp: libc_timestamp_to_instant(recv_result.timestamp),
            };

            log::trace!("Recv TC");

            Ok(packet)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::interface::LinuxNetworkMode;

    #[tokio::test]
    async fn port_setup_ipv4() -> Result<(), Box<dyn std::error::Error>> {
        let port = 9000;

        let interface = InterfaceDescriptor {
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
        let port = 9001;

        let interface = InterfaceDescriptor {
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
}
