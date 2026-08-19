use std::{io::ErrorKind, os::fd::RawFd};

use libc::recv;
use tokio::io::{unix::AsyncFd, Interest};

use crate::{cerr, control_message::zeroed_sockaddr_storage};

use super::InterfaceName;

pub struct ChangeDetector {
    fd: AsyncFd<RawFd>,
}

impl ChangeDetector {
    const SOCKET_PATH: &'static [u8] = b"/var/run/devd.seqpacket.pipe";
    pub fn new() -> std::io::Result<Self> {
        const _: () = assert!(
            std::mem::size_of::<libc::sockaddr_storage>()
                >= std::mem::size_of::<libc::sockaddr_un>()
        );
        const _: () = assert!(
            std::mem::align_of::<libc::sockaddr_storage>()
                >= std::mem::align_of::<libc::sockaddr_un>()
        );

        let mut address_buf = zeroed_sockaddr_storage();
        // Safety: the above assertions guarantee that alignment and size are correct.
        // the resulting reference won't outlast the function, and result lives the entire
        // duration of the function
        let address = unsafe {
            &mut *(&mut address_buf as *mut libc::sockaddr_storage as *mut libc::sockaddr_un)
        };

        address.sun_family = libc::AF_UNIX as _;
        for i in 0..Self::SOCKET_PATH.len() {
            address.sun_path[i] = Self::SOCKET_PATH[i] as _;
        }

        // Safety: calling socket is safe
        let fd = cerr(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) })?;
        // Safety: address is valid for the duration of the call
        cerr(unsafe {
            libc::connect(
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

pub fn lookup_phc(_interface: InterfaceName) -> Option<u32> {
    None
}
