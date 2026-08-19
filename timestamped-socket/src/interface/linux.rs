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

/// Get the hardware clock index associated with the given interface.
#[allow(
    clippy::cast_possible_wrap,
    reason = "Interface indices are always positive."
)]
#[expect(
    clippy::cast_sign_loss,
    reason = "Interface indices are always positive."
)]
#[must_use]
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
            ifru_data: (&raw mut ethtool_ts_info).cast(),
        },
    };

    // Safety: request and ethtool_ts_info are live for the duration of the call.
    let error = unsafe {
        ioctl(
            fd,
            SIOCETHTOOL as _,
            (&raw mut request).cast::<libc::c_void>(),
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

/// A detector for changes to which network interfaces are available on the system.
pub struct ChangeDetector {
    fd: AsyncFd<RawFd>,
}

impl ChangeDetector {
    /// Create a new detector for changes to which network interfaces are available on the system.
    ///
    /// # Errors
    /// May fail if the system does not allow a new change detector to be created.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Network addresses are small enought that their size fits in an integer."
    )]
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
        let address = unsafe { &mut *(&raw mut address_buf).cast::<libc::sockaddr_nl>() };

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
                std::ptr::from_mut(address).cast(),
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

    #[expect(
        clippy::cast_possible_truncation,
        reason = "The message buffer is small enought that its size fits in an integer."
    )]
    fn empty(fd: i32) {
        loop {
            // Safety: buf is valid for the duration of the call, and it's length is passed as the len argument
            let mut buf = [0u8; 16];
            match cerr(unsafe {
                recv(
                    fd,
                    (&raw mut buf).cast(),
                    std::mem::size_of_val(&buf) as _,
                    0,
                ) as _
            }) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::error!("Could not receive on change socket: {}", e);
                    break;
                }
            }
        }
    }

    /// Wait for a change to which network interfaces are present.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "The message buffer is small enought that its size fits in an integer."
    )]
    pub async fn wait_for_change(&mut self) {
        if let Err(e) = self
            .fd
            .async_io(Interest::READABLE, |fd| {
                // Safety: buf is valid for the duration of the call, and it's length is passed as the len argument
                let mut buf = [0u8; 16];
                cerr(unsafe {
                    recv(
                        *fd,
                        (&raw mut buf).cast(),
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
