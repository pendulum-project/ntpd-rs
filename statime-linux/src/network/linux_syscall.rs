use std::ffi::CString;

use nix::ioctl_readwrite_bad;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HwtstampConfig {
    pub flags: libc::c_int,
    pub tx_type: libc::c_int,
    pub rx_filter: libc::c_int,
}

const HWTSTAMP_TX_ON: libc::c_int = 1;
const HWTSTAMP_FILTER_ALL: libc::c_int = 1;

const SIOCSHWTSTAMP: u16 = 0x89b0;

ioctl_readwrite_bad!(siocshwtstamp, SIOCSHWTSTAMP, libc::ifreq);

pub fn driver_enable_hardware_timestamping(socket: i32, interface: &str) {
    let mut tstamp_config = HwtstampConfig {
        flags: 0,
        tx_type: HWTSTAMP_TX_ON,
        rx_filter: HWTSTAMP_FILTER_ALL,
    };

    let ifname = CString::new(interface).expect("Cannot convert interface name to C string");
    if ifname.as_bytes_with_nul().len() > libc::IFNAMSIZ {
        panic!("Interface name too long");
    }

    let mut it = ifname.as_bytes_with_nul().iter();
    let ifr_name = std::array::from_fn(|_| it.next().copied().unwrap_or_default() as i8);

    let mut ifreq = libc::ifreq {
        ifr_name,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
        },
    };

    unsafe { siocshwtstamp(socket, &mut ifreq as *mut _) }
        .expect("Failed to enable hardware timestamping in the driver");
}
