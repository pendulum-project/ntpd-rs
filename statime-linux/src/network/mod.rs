#![forbid(unsafe_code)]

//! Implementation of the abstract network types for the linux platform

use std::{
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use clock_steering::Clock;
use statime::{Time, MAX_DATA_LEN};
use timestamped_socket::{
    interface::{InterfaceDescriptor, InterfaceIterator},
    raw_udp_socket::{RawUdpSocket, TimestampingMode},
    timestamped_udp_socket::{LibcTimestamp, TimestampedUdpSocket},
};
use tokio::io::{unix::AsyncFd, Interest};

fn join_multicast(
    interface: &InterfaceDescriptor,
    socket: &std::net::UdpSocket,
) -> std::io::Result<SocketAddr> {
    const IPV6_PRIMARY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x0e, 0, 0, 0, 0, 0x01, 0x81);
    const IPV6_PDELAY_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff, 0x02, 0, 0, 0, 0, 0, 0x6b);

    const IPV4_PRIMARY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
    const IPV4_PDELAY_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

    let port = socket.local_addr()?.port();

    match interface.get_address()? {
        IpAddr::V4(ip) => {
            // TODO: multicast ttl limit for ipv4

            socket.join_multicast_v4(&IPV4_PRIMARY_MULTICAST, &ip)?;
            socket.join_multicast_v4(&IPV4_PDELAY_MULTICAST, &ip)?;

            Ok((IPV4_PRIMARY_MULTICAST, port).into())
        }
        IpAddr::V6(_ip) => {
            // TODO: multicast hops limit for ipv6

            // 0 indicates any interface, though it is likely this interface does not
            // support multicast
            let if_index = interface.get_index().unwrap_or(0);

            socket.join_multicast_v6(&IPV6_PRIMARY_MULTICAST, if_index)?;
            socket.join_multicast_v6(&IPV6_PDELAY_MULTICAST, if_index)?;

            Ok((IPV6_PRIMARY_MULTICAST, port).into())
        }
    }
}

pub struct EventSocket {
    socket: TimestampedUdpSocket,
    address: SocketAddr,
}

pub struct EventPacket<'a> {
    pub data: &'a [u8],
    pub timestamp: Time,
}

impl EventSocket {
    /// The time-critical port
    pub const PORT: u16 = 319;

    pub async fn new(
        interface: &InterfaceDescriptor,
        timestamping_mode: TimestampingMode,
    ) -> std::io::Result<Self> {
        let bind_ip = interface.mode.unspecified_ip_addr();
        let addr = SocketAddr::new(bind_ip, Self::PORT);

        log::info!("Binding time critical socket on {addr}");

        let socket = RawUdpSocket::new_into_std(addr, interface.interface_name)?;
        let address = join_multicast(&interface, &socket)?;

        Ok(Self {
            socket: TimestampedUdpSocket::from_udp_socket(socket, timestamping_mode)?,
            address,
        })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<Option<statime::Time>, std::io::Error> {
        log::trace!("Send TC");

        let opt_libc_ts = self.socket.send(data, self.address).await?;

        Ok(opt_libc_ts.map(libc_timestamp_to_instant))
    }

    pub async fn recv<'a>(
        &mut self,
        clock: &impl Clock,
        buf: &'a mut [u8; MAX_DATA_LEN],
    ) -> Result<EventPacket<'a>, std::io::Error> {
        let recv_result = self.socket.recv(clock, buf).await?;

        let packet = EventPacket {
            data: &buf[..recv_result.bytes_read],
            timestamp: libc_timestamp_to_instant(recv_result.timestamp),
        };

        log::trace!("Recv TC");

        Ok(packet)
    }
}

pub struct GeneralSocket {
    socket: AsyncFd<std::net::UdpSocket>,
    address: SocketAddr,
}

pub struct GeneralPacket<'a> {
    pub data: &'a [u8],
}

impl GeneralSocket {
    /// The non-time-critical port
    pub const PORT: u16 = 320;

    pub async fn new(interface: &InterfaceDescriptor) -> std::io::Result<Self> {
        let bind_ip = interface.mode.unspecified_ip_addr();
        let addr = SocketAddr::new(bind_ip, Self::PORT);

        log::info!("Binding non time critical socket on {addr}");

        let socket = RawUdpSocket::new_into_std(addr, interface.interface_name)?;
        let address = join_multicast(&interface, &socket)?;

        Ok(Self {
            socket: AsyncFd::new(socket)?,
            address,
        })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        log::trace!("Send NTC");

        let sender = |inner: &std::net::UdpSocket| inner.send_to(data, self.address);
        self.socket.async_io(Interest::WRITABLE, sender).await?;

        Ok(())
    }

    pub async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> std::io::Result<GeneralPacket<'a>> {
        let (received_len, _) = self
            .socket
            .async_io(Interest::READABLE, |inner| inner.recv_from(buf))
            .await?;
        log::trace!("Recv NTC");

        if received_len > MAX_DATA_LEN {
            Err(io::Error::new(ErrorKind::InvalidData, "too long"))
        } else {
            let data = &buf[..received_len];
            Ok(GeneralPacket { data })
        }
    }
}

fn libc_timestamp_to_instant(ts: LibcTimestamp) -> Time {
    match ts {
        LibcTimestamp::TimeSpec { seconds, nanos } => {
            Time::from_fixed_nanos(seconds as i128 * 1_000_000_000i128 + nanos as i128)
        }
        LibcTimestamp::TimeVal { seconds, micros } => {
            Time::from_fixed_nanos(seconds as i128 * 1_000_000_000i128 + micros as i128 * 1_000)
        }
    }
}

#[cfg(test)]
mod tests {
    use timestamped_socket::interface::LinuxNetworkMode;

    use super::*;

    #[tokio::test]
    async fn port_setup_ipv4() -> Result<(), Box<dyn std::error::Error>> {
        let port = 9000;

        let interface = InterfaceDescriptor {
            interface_name: None,
            mode: LinuxNetworkMode::Ipv4,
        };

        let addr = SocketAddr::new(interface.mode.unspecified_ip_addr(), port);

        let socket = RawUdpSocket::new_into_std(addr, interface.interface_name)?;
        let address = join_multicast(&interface, &socket)?;

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
        let address = join_multicast(&interface, &socket)?;

        assert_ne!(address.ip(), interface.mode.unspecified_ip_addr());
        assert_eq!(address.port(), port);

        Ok(())
    }
}
