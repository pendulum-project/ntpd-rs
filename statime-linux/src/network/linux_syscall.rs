use std::os::fd::AsRawFd;

use super::{interface::InterfaceName, linux::cerr};

pub fn driver_enable_hardware_timestamping(
    udp_socket: &std::net::UdpSocket,
    interface: InterfaceName,
) {
    let mut tstamp_config = libc::hwtstamp_config {
        flags: 0,
        tx_type: libc::HWTSTAMP_TX_ON as _,
        rx_filter: libc::HWTSTAMP_FILTER_ALL as _,
    };

    let mut ifreq = libc::ifreq {
        ifr_name: interface.to_ifr_name(),
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
        },
    };

    let fd = udp_socket.as_raw_fd();
    cerr(unsafe { libc::ioctl(fd, libc::SIOCGHWTSTAMP as _, &mut ifreq) })
        .expect("Failed to enable hardware timestamping in the driver");
}
