use std::{ffi::CString, intrinsics::transmute};

use nix::ioctl_readwrite_bad;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ifmap {
    pub mem_start: libc::c_ulong,
    pub mem_end: libc::c_ulong,
    pub base_addr: libc::c_ushort,
    pub irq: libc::c_char,
    pub dma: libc::c_char,
    pub port: libc::c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfrIfrn {
    pub ifrn_name: [libc::c_char; libc::IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfrIfru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_netmask: libc::sockaddr,
    pub ifru_hwaddr: libc::sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_ivalue: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_map: Ifmap,
    pub ifru_slave: [libc::c_char; libc::IFNAMSIZ],
    pub ifru_newname: [libc::c_char; libc::IFNAMSIZ],
    pub ifru_data: *mut libc::c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ifreq {
    pub ifr_ifrn: IfrIfrn,
    pub ifr_ifru: IfrIfru,
}

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

ioctl_readwrite_bad!(siocshwtstamp, SIOCSHWTSTAMP, Ifreq);

pub fn driver_enable_hardware_timestamping(socket: i32, interface: &str) {
    let mut tstamp_config = HwtstampConfig {
        flags: 0,
        tx_type: HWTSTAMP_TX_ON,
        rx_filter: HWTSTAMP_FILTER_ALL,
    };

    let mut ifreq = Ifreq {
        ifr_ifrn: IfrIfrn {
            ifrn_name: [0; libc::IFNAMSIZ],
        },
        ifr_ifru: IfrIfru {
            ifru_data: unsafe { transmute(&mut tstamp_config as *mut _) },
        },
    };

    let ifname = CString::new(interface).expect("Cannot convert interface name to C string");
    if ifname.as_bytes_with_nul().len() > libc::IFNAMSIZ {
        panic!("Interface name too long");
    }

    for (from, to) in ifname
        .as_bytes_with_nul()
        .iter()
        .zip(unsafe { ifreq.ifr_ifrn.ifrn_name.iter_mut() })
    {
        *to = *from as _;
    }

    unsafe { siocshwtstamp(socket, &mut ifreq as *mut _) }
        .expect("Failed to enable hardware timestamping in the driver");
}
