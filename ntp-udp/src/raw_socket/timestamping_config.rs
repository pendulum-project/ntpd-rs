use std::os::unix::prelude::AsRawFd;

use super::cerr;
use crate::interface_name;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TimestampingConfig {
    pub(crate) rx_software: bool,
    pub(crate) tx_software: bool,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default)]
struct ethtool_ts_info {
    cmd: u32,
    so_timestamping: u32,
    phc_index: u32,
    tx_types: u32,
    tx_reserved: [u32; 3],
    rx_filters: u32,
    rx_reserved: [u32; 3],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifrn_name: [u8; 16],
    ifru_data: *mut libc::c_void,
    __empty_space: [u8; 40 - 8],
}

impl TimestampingConfig {
    /// Enable all timestamping options that are supported by this crate and the hardware/software
    /// of the device we're running on
    #[allow(dead_code)]
    pub(crate) fn all_supported(udp_socket: &std::net::UdpSocket) -> std::io::Result<Self> {
        // Get time stamping and PHC info
        const ETHTOOL_GET_TS_INFO: u32 = 0x00000041;

        let mut tsi: ethtool_ts_info = ethtool_ts_info {
            cmd: ETHTOOL_GET_TS_INFO,
            ..Default::default()
        };

        let fd = udp_socket.as_raw_fd();

        if let Some(ifrn_name) = interface_name::interface_name(udp_socket.local_addr()?)? {
            let ifr: ifreq = ifreq {
                ifrn_name,
                ifru_data: (&mut tsi as *mut _) as *mut libc::c_void,
                __empty_space: [0; 40 - 8],
            };

            const SIOCETHTOOL: u64 = 0x8946;
            cerr(unsafe { libc::ioctl(fd, SIOCETHTOOL, &ifr) }).unwrap();

            let support = Self {
                rx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_RX_SOFTWARE != 0,
                tx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_TX_SOFTWARE != 0,
            };

            // per the documentation of `SOF_TIMESTAMPING_RX_SOFTWARE`:
            //
            // > Request rx timestamps when data enters the kernel. These timestamps are generated
            // > just after a device driver hands a packet to the kernel receive stack.
            //
            // the linux kernal should always support receive software timestamping
            assert!(support.rx_software);

            Ok(support)
        } else {
            Ok(Self::default())
        }
    }
}
