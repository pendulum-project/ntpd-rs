use std::os::fd::AsRawFd;

use crate::{interface_name, raw_socket::cerr};

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

pub fn driver_enable_hardware_timestamping(
    udp_socket: &std::net::UdpSocket,
) -> std::io::Result<()> {
    let mut tstamp_config = hwtimestamp_config {
        flags: 0,
        tx_type: HWTSTAMP_TX_ON,
        rx_filter: HWTSTAMP_FILTER_ALL,
    };

    if let Some(ifr_name) = interface_name::interface_name(udp_socket.local_addr()?)? {
        let mut ifreq: libc::ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
            },
        };

        let fd = udp_socket.as_raw_fd();
        cerr(unsafe { libc::ioctl(fd, SIOCSHWTSTAMP as libc::c_ulong, &mut ifreq) })?;

        let mut tstamp_config = hwtimestamp_config {
            flags: 0,
            tx_type: 0,
            rx_filter: 0,
        };

        let mut ifreq: libc::ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
            },
        };

        let fd = udp_socket.as_raw_fd();
        cerr(unsafe { libc::ioctl(fd, SIOCGHWTSTAMP as libc::c_ulong, &mut ifreq) })?;

        dbg!(tstamp_config);

        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "socket has no interface name",
        ))
    }
}
