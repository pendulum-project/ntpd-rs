use std::os::unix::io::AsRawFd;

use crate::{interface::InterfaceName, raw_socket::cerr};

const fn standard_hwtstamp_config() -> libc::hwtstamp_config {
    libc::hwtstamp_config {
        flags: 0,
        tx_type: libc::HWTSTAMP_TX_ON as _,
        rx_filter: libc::HWTSTAMP_FILTER_ALL as _,
    }
}

pub fn driver_enable_hardware_timestamping(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<()> {
    set_hardware_timestamp(udp_socket, standard_hwtstamp_config())
}

fn set_hardware_timestamp(
    udp_socket: &std::net::UdpSocket,
    mut config: libc::hwtstamp_config,
) -> std::io::Result<()> {
    let mut ifreq: libc::ifreq = libc::ifreq {
        ifr_name: socket_interface_name(udp_socket)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_data: (&mut config as *mut _) as *mut libc::c_char,
        },
    };

    let fd = udp_socket.as_raw_fd();
    cerr(unsafe { libc::ioctl(fd, libc::SIOCSHWTSTAMP as _, &mut ifreq) })?;

    Ok(())
}

#[allow(unused)]
fn get_hardware_timestamp(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<libc::hwtstamp_config> {
    let mut tstamp_config = libc::hwtstamp_config {
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
    cerr(unsafe { libc::ioctl(fd, libc::SIOCGHWTSTAMP as _, &mut ifreq) })?;

    Ok(tstamp_config)
}

fn socket_interface_name(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    use std::io::{Error, ErrorKind};

    match InterfaceName::from_socket_addr(udp_socket.local_addr()?)? {
        Some(interface_name) => Ok(interface_name.to_ifr_name()),
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

        if let Err(e) = get_hardware_timestamp(&udp_socket) {
            assert!(
                e.to_string().contains("Operation not supported")
                    || e.to_string().contains("Not supported")
            );
        }

        Ok(())
    }

    #[test]
    #[ignore = "requires elevated permissions to run"]
    fn get_set_hwtimestamp() -> std::io::Result<()> {
        let udp_socket = std::net::UdpSocket::bind(("0.0.0.0", 9002))?;
        udp_socket.connect(("10.0.0.18", 9003))?;

        let old = get_hardware_timestamp(&udp_socket)?;

        let custom = standard_hwtstamp_config();

        set_hardware_timestamp(&udp_socket, custom)?;
        let new = get_hardware_timestamp(&udp_socket)?;

        let custom = standard_hwtstamp_config();
        assert_eq!(new.flags, custom.flags);
        assert_eq!(new.tx_type, custom.tx_type);
        assert_eq!(new.rx_filter, custom.rx_filter);

        set_hardware_timestamp(&udp_socket, old)?;

        Ok(())
    }
}
