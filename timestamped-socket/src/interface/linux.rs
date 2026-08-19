use std::{array, io::ErrorKind, os::fd::RawFd};

use libc::{
    __c_anonymous_ifr_ifru, close, ifreq, ioctl, recv, socket, AF_INET, SIOCETHTOOL, SOCK_DGRAM,
};
use tokio::io::{unix::AsyncFd, Interest};

use crate::{cerr, control_message::zeroed_sockaddr_storage};

use super::InterfaceName;

#[repr(C)]
struct EthtoolTsInfo {
    cmd: u32,
    so_timestamping: u32,
    phc_index: i32,
    tx_types: u32,
    reserved1: [u32; 3],
    rx_filters: u32,
    reserved2: [u32; 3],
}

const ETHTOOL_GET_TS_INFO: u32 = 0x41;

pub fn lookup_phc(interface: InterfaceName) -> Option<u32> {
    // Safety: socket is safe to call with these constants as
    // arguments
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        tracing::error!("Could not open socket for looking up PHC index");
        return None;
    }

    let mut ethtool_ts_info = EthtoolTsInfo {
        cmd: ETHTOOL_GET_TS_INFO,
        so_timestamping: 0,
        phc_index: -1,
        tx_types: 0,
        reserved1: [0; 3],
        rx_filters: 0,
        reserved2: [0; 3],
    };

    let mut request = ifreq {
        ifr_name: array::from_fn(|i| interface.bytes[i] as _),
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_data: &mut ethtool_ts_info as *mut _ as *mut _,
        },
    };

    // Safety: request and ethtool_ts_info are live for the duration of the call.
    let error = unsafe {
        ioctl(
            fd,
            SIOCETHTOOL as _,
            &mut request as *mut _ as *mut libc::c_void,
        )
    };

    // should always close fd
    // Safety: Safe to call close for this file descriptor
    unsafe {
        close(fd);
    }

    if error < 0 {
        None
    } else if ethtool_ts_info.phc_index >= 0 {
        Some(ethtool_ts_info.phc_index as u32)
    } else {
        None
    }
}

pub struct ChangeDetector {
    fd: AsyncFd<RawFd>,
}

impl ChangeDetector {
    pub fn new() -> std::io::Result<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_nl>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_nl>()
        );

        let mut address_buf = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let address = unsafe {
            &mut *(&mut address_buf as *mut libc::sockaddr_storage as *mut libc::sockaddr_nl)
        };

        address.nl_family = libc::AF_NETLINK as _;
        address.nl_groups =
            (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR | libc::RTMGRP_LINK) as _;

        // Safety: calling socket is safe
        let fd =
            cerr(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) })?;
        // Safety: address is valid for the duration of the call
        cerr(unsafe {
            libc::bind(
                fd,
                address as *mut _ as *mut _,
                std::mem::size_of_val(address) as _,
            )
        })?;

        let nonblocking = 1 as libc::c_int;
        // Safety: nonblocking lives for the duration of the call, and is 4 bytes long as expected for FIONBIO
        cerr(unsafe { libc::ioctl(fd, libc::FIONBIO, &nonblocking) })?;

        Ok(ChangeDetector {
            fd: AsyncFd::new(fd)?,
        })
    }

    fn empty(fd: i32) {
        loop {
            // Safety: buf is valid for the duration of the call, and it's length is passed as the len argument
            let mut buf = [0u8; 16];
            match cerr(unsafe {
                recv(
                    fd,
                    &mut buf as *mut _ as *mut _,
                    std::mem::size_of_val(&buf) as _,
                    0,
                ) as _
            }) {
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::error!("Could not receive on change socket: {}", e);
                    break;
                }
            }
        }
    }

    pub async fn wait_for_change(&mut self) {
        if let Err(e) = self
            .fd
            .async_io(Interest::READABLE, |fd| {
                // Safety: buf is valid for the duration of the call, and it's length is passed as the len argument
                let mut buf = [0u8; 16];
                cerr(unsafe {
                    recv(
                        *fd,
                        &mut buf as *mut _ as *mut _,
                        std::mem::size_of_val(&buf) as _,
                        0,
                    ) as _
                })?;
                Self::empty(*fd);
                Ok(())
            })
            .await
        {
            tracing::error!("Could not receive on change socket: {}", e);
        }
    }
}
