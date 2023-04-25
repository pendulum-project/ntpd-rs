use nix::ioctl_readwrite_bad;

use super::linux::InterfaceName;

ioctl_readwrite_bad!(siocshwtstamp, libc::SIOCSHWTSTAMP, libc::ifreq);

pub fn driver_enable_hardware_timestamping(socket: i32, interface: InterfaceName) {
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

    unsafe { siocshwtstamp(socket, &mut ifreq as *mut _) }
        .expect("Failed to enable hardware timestamping in the driver");
}
