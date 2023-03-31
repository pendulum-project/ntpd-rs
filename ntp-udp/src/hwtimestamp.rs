use std::os::unix::io::AsRawFd;

use crate::{interface_name, raw_socket::cerr};

pub fn driver_enable_hardware_timestamping(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<()> {
    let tstamp_config = hwtimestamp_config {
        flags: 0,
        tx_type: HWTSTAMP_TX_ON,
        rx_filter: HWTSTAMP_FILTER_ALL,
    };

    set_hardware_timestamp(udp_socket, tstamp_config)
}

const HWTSTAMP_TX_ON: libc::c_int = 1;
const HWTSTAMP_FILTER_ALL: libc::c_int = 1;

const SIOCSHWTSTAMP: u16 = 0x89b0;
const SIOCGHWTSTAMP: u16 = 0x89b1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct hwtimestamp_config {
    pub flags: libc::c_int,
    pub tx_type: libc::c_int,
    pub rx_filter: libc::c_int,
}

fn set_hardware_timestamp(
    udp_socket: &std::net::UdpSocket,
    mut config: hwtimestamp_config,
) -> std::io::Result<()> {
    let mut ifreq: libc::ifreq = libc::ifreq {
        ifr_name: socket_interface_name(udp_socket)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_data: (&mut config as *mut _) as *mut libc::c_char,
        },
    };

    let fd = udp_socket.as_raw_fd();
    cerr(unsafe { libc::ioctl(fd, SIOCSHWTSTAMP as libc::c_ulong, &mut ifreq) })?;

    Ok(())
}

#[allow(unused)]
fn get_hardware_timestamp(udp_socket: &std::net::UdpSocket) -> std::io::Result<hwtimestamp_config> {
    let mut tstamp_config = hwtimestamp_config {
        flags: 0,
        tx_type: 0,
        rx_filter: 0,
    };

    let mut ifreq: libc::ifreq = libc::ifreq {
        ifr_name: socket_interface_name(udp_socket)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
        },
    };

    let fd = udp_socket.as_raw_fd();
    cerr(unsafe { libc::ioctl(fd, SIOCGHWTSTAMP as libc::c_ulong, &mut ifreq) })?;

    Ok(tstamp_config)
}

fn socket_interface_name(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<[i8; libc::IFNAMSIZ]> {
    use std::io::{Error, ErrorKind};

    match interface_name::interface_name(udp_socket.local_addr()?)? {
        Some(ifr_name) => Ok(ifr_name),
        None => Err(Error::new(ErrorKind::Other, "socket has no interface name")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hwtimestamp() -> std::io::Result<()> {
        let udp_socket = std::net::UdpSocket::bind(("0.0.0.0", 9000))?;
        udp_socket.connect(("10.0.0.18", 9001))?;

        let _ = get_hardware_timestamp(&udp_socket)?;

        Ok(())
    }

    #[test]
    #[ignore = "requires elevated permissions to run"]
    fn get_set_hwtimestamp() -> std::io::Result<()> {
        let udp_socket = std::net::UdpSocket::bind(("0.0.0.0", 9002))?;
        udp_socket.connect(("10.0.0.18", 9003))?;

        let old = get_hardware_timestamp(&udp_socket)?;

        let custom = hwtimestamp_config {
            flags: 0,
            tx_type: HWTSTAMP_TX_ON,
            rx_filter: HWTSTAMP_FILTER_ALL,
        };

        set_hardware_timestamp(&udp_socket, custom)?;
        let new = get_hardware_timestamp(&udp_socket)?;

        assert_eq!(new.flags, 0);
        assert_eq!(new.tx_type, HWTSTAMP_TX_ON);
        assert_eq!(new.rx_filter, HWTSTAMP_FILTER_ALL);

        set_hardware_timestamp(&udp_socket, old)?;

        Ok(())
    }
}
