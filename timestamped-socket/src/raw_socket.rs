use std::{
    io::IoSliceMut,
    mem::transmute,
    os::fd::{AsRawFd, RawFd},
    ptr::write_unaligned,
};

use libc::{c_void, in6_addr, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage};

use crate::{
    cerr,
    control_message::{
        empty_cmsghdr, empty_msghdr, zeroed_sockaddr_storage, ControlMessage,
        ControlMessageIterator, MessageQueue,
    },
};

#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "linux")))]
mod fallback;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

// A struct providing safe wrappers around various socket api calls
#[derive(Debug, Hash)]
pub(crate) struct RawSocket {
    fd: RawFd,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl RawSocket {
    pub(crate) fn open(
        domain: libc::c_int,
        ty: libc::c_int,
        protocol: libc::c_int,
    ) -> std::io::Result<Self> {
        // Safety: libc::socket is always safe to call
        Ok(RawSocket {
            fd: cerr(unsafe { libc::socket(domain, ty, protocol) })?,
        })
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "a c_int is always short enough that its size fits in an i32."
    )]
    pub(crate) fn ipv6_only(&self) -> std::io::Result<()> {
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                std::ptr::from_ref(&(1 as libc::c_int)).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "a c_int is always short enough that its size fits in an i32."
    )]
    pub(crate) fn enable_destination_ipv6(&self) -> std::io::Result<()> {
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                std::ptr::from_ref(&(1 as libc::c_int)).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    pub(crate) fn bind(&self, addr: sockaddr_storage) -> std::io::Result<()> {
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety: socket is valid for the duration of the call, addr lives for the duration of
        // the call and len is at most the length of addr.
        cerr(unsafe { libc::bind(self.fd, (&raw const addr).cast(), len) })?;
        Ok(())
    }

    pub(crate) fn connect(&self, addr: sockaddr_storage) -> std::io::Result<()> {
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety: socket is valid for the duration of the call, addr lives for the duration of
        // the call and len is at most the length of addr.
        cerr(unsafe { libc::connect(self.fd, (&raw const addr).cast(), len) })?;
        Ok(())
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        let nonblocking = libc::c_int::from(nonblocking);
        // Safety: nonblocking lives for the duration of the call, and is 4 bytes long as expected for FIONBIO
        cerr(unsafe { libc::ioctl(self.fd, libc::FIONBIO, &nonblocking) }).map(drop)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "options is always short enough that its size fits in an i32."
    )]
    #[cfg(target_os = "linux")]
    pub(crate) fn reuse_addr(&self) -> std::io::Result<()> {
        let options = 1u32;

        // Safety:
        //
        // the pointer argument is valid, the size is accurate
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&raw const options).cast::<libc::c_void>(),
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Message is always short enough that its size fits in an i32."
    )]
    pub(crate) fn receive_message<'a>(
        &self,
        packet_buf: &mut [u8],
        control_buf: &'a mut [u8],
        queue: MessageQueue,
    ) -> std::io::Result<(
        usize,
        impl Iterator<Item = ControlMessage> + 'a,
        sockaddr_storage,
    )> {
        let mut buf_slice = IoSliceMut::new(packet_buf);
        let mut addr = zeroed_sockaddr_storage();

        let mut mhdr = empty_msghdr();

        mhdr.msg_control = control_buf.as_mut_ptr().cast::<libc::c_void>();
        mhdr.msg_controllen = control_buf.len() as _;
        mhdr.msg_iov = (&raw mut buf_slice).cast::<libc::iovec>();
        mhdr.msg_iovlen = 1;
        mhdr.msg_flags = 0;
        mhdr.msg_name = (&raw mut addr).cast::<libc::c_void>();
        mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;

        let receive_flags = match queue {
            MessageQueue::Normal => 0,
            #[cfg(target_os = "linux")]
            MessageQueue::Error => libc::MSG_ERRQUEUE,
        };

        // Safety:
        // We have a mutable reference to the control buffer for the duration of the
        // call, and controllen is also set to it's length.
        // IoSliceMut is ABI compatible with iovec, and we only have 1 which matches
        // iovlen msg_name is initialized to point to an owned sockaddr_storage and
        // msg_namelen is the size of sockaddr_storage
        // If one of the buffers is too small, recvmsg cuts off data at appropriate
        // boundary
        let received_bytes = loop {
            match cerr(unsafe { libc::recvmsg(self.fd, &raw mut mhdr, receive_flags) } as _) {
                Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                    // retry when the recv was interrupted
                }
                Err(e) => return Err(e),
                #[expect(clippy::cast_sign_loss, reason = "cerr ensures this is not negative")]
                Ok(sent) => break sent as usize,
            }
        };

        if mhdr.msg_flags & libc::MSG_TRUNC > 0 && !packet_buf.is_empty() {
            tracing::debug!(
                "truncated packet because it was larger than expected: {} bytes",
                packet_buf.len(),
            );
        }

        if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
            tracing::debug!("truncated control messages");
        }

        // Clear out the fields for which we are giving up the reference
        mhdr.msg_iov = std::ptr::null_mut();
        mhdr.msg_iovlen = 0;
        mhdr.msg_name = std::ptr::null_mut();
        mhdr.msg_namelen = 0;

        // Safety:
        // recvmsg ensures that the control buffer contains
        // a set of valid control messages and that controllen is
        // the length these take up in the buffer.
        Ok((
            received_bytes,
            unsafe { ControlMessageIterator::new(mhdr) },
            addr,
        ))
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Message is always short enough that its size fits in an i32."
    )]
    pub(crate) fn send_to(&self, msg: &[u8], addr: sockaddr_storage) -> std::io::Result<()> {
        // Per posix, it may be invalid to specify a length larger than that of the family.
        let len = sockaddr_len(addr);

        // Safety:
        // the socket will outlive the call.
        // msg points to a block of memory of length msg.len()
        // addr points to a block of memory of length at least len
        // with flags=0, the other arguments don't matter for safety
        cerr(unsafe {
            libc::sendto(
                self.fd,
                std::ptr::from_ref(msg).cast::<c_void>(),
                msg.len(),
                0,
                (&raw const addr).cast::<sockaddr>(),
                len,
            ) as _
        })?;
        Ok(())
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Message is always short enough that its size fits in an i32."
    )]
    pub(crate) fn send(&self, msg: &[u8]) -> std::io::Result<()> {
        // Safety:
        // msg points to a block of memory of length msg.len()
        // with flags=0, the other arguments don't matter for safety
        cerr(unsafe {
            libc::send(
                self.fd,
                std::ptr::from_ref(msg).cast::<c_void>(),
                msg.len(),
                0,
            ) as _
        })?;
        Ok(())
    }

    pub(crate) fn send_from_to(
        &self,
        msg: &[u8],
        from: sockaddr_storage,
        to: sockaddr_storage,
    ) -> std::io::Result<()> {
        match libc::c_int::from(from.ss_family) {
            libc::AF_INET => {
                // Safety:
                // Transmuting &sockaddr_storage into another sockaddr reference type is safe, and in this case the lifetimes work out.
                let from = unsafe { transmute::<&sockaddr_storage, &sockaddr_in>(&from) };
                self.send_from_to_v4(msg, from.sin_addr, to)
            }
            libc::AF_INET6 => {
                // Safety:
                // Transmuting &sockaddr_storage into another sockaddr reference type is safe, and in this case the lifetimes work out.
                let from = unsafe { transmute::<&sockaddr_storage, &sockaddr_in6>(&from) };
                self.send_from_to_v6(msg, from.sin6_addr, to)
            }
            _ => Err(std::io::ErrorKind::InvalidInput.into()),
        }
    }

    pub(crate) fn send_from(&self, msg: &[u8], addr: sockaddr_storage) -> std::io::Result<()> {
        match libc::c_int::from(addr.ss_family) {
            libc::AF_INET => {
                // Safety:
                // Transmuting &sockaddr_storage into another sockaddr reference type is safe, and in this case the lifetimes work out.
                let from = unsafe { transmute::<&sockaddr_storage, &sockaddr_in>(&addr) };
                self.send_from_v4(msg, from.sin_addr)
            }
            libc::AF_INET6 => {
                // Safety:
                // Transmuting &sockaddr_storage into another sockaddr reference type is safe, and in this case the lifetimes work out.
                let from = unsafe { transmute::<&sockaddr_storage, &sockaddr_in6>(&addr) };
                self.send_from_v6(msg, from.sin6_addr)
            }
            _ => Err(std::io::ErrorKind::InvalidInput.into()),
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Message is always short enough that its size fits in an i32."
    )]
    pub(crate) fn send_from_v6(&self, msg: &[u8], addr: in6_addr) -> std::io::Result<()> {
        let control_message = control_message(
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            libc::in6_pktinfo {
                ipi6_addr: addr,
                ipi6_ifindex: 0,
            },
        );

        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *mut libc::c_void,
            iov_len: msg.len(),
        };

        let mut msghdr = empty_msghdr();
        msghdr.msg_iov = &raw mut iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = control_message.as_ptr() as *mut _;
        msghdr.msg_controllen = control_message.len() as _;

        // Safety:
        // msghdr is valid.
        cerr(unsafe { libc::sendmsg(self.fd, &raw const msghdr, 0) } as _).map(|_| {})
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Message is always short enough that its size fits in an i32."
    )]
    pub(crate) fn send_from_to_v6(
        &self,
        msg: &[u8],
        from: in6_addr,
        to: sockaddr_storage,
    ) -> std::io::Result<()> {
        let to_len = sockaddr_len(to);

        let control_message = control_message(
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            libc::in6_pktinfo {
                ipi6_addr: from,
                ipi6_ifindex: 0,
            },
        );

        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *mut libc::c_void,
            iov_len: msg.len(),
        };

        let mut msghdr = empty_msghdr();
        msghdr.msg_name = &raw const to as *mut _;
        msghdr.msg_namelen = to_len;
        msghdr.msg_iov = &raw mut iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = control_message.as_ptr() as *mut _;
        msghdr.msg_controllen = control_message.len() as _;

        // Safety:
        // msghdr is valid.
        cerr(unsafe { libc::sendmsg(self.fd, &raw const msghdr, 0) } as _).map(|_| {})
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "sockaddr_storage is always small enough for its size to fit in the destination type."
    )]
    pub(crate) fn getsockname(&self) -> std::io::Result<sockaddr_storage> {
        let mut addr = zeroed_sockaddr_storage();
        let mut addr_len: libc::socklen_t = std::mem::size_of_val(&addr) as _;
        // Safety:
        // the socket will outlive the call.
        // addr points to a block of memory of length addr_len
        // addr_len will outlive the call.
        cerr(unsafe { libc::getsockname(self.fd, (&raw mut addr).cast(), &raw mut addr_len) })?;
        Ok(addr)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "sockaddr_storage is always small enough for its size to fit in the destination type."
    )]
    pub(crate) fn getpeername(&self) -> std::io::Result<sockaddr_storage> {
        let mut addr = zeroed_sockaddr_storage();
        let mut addr_len: libc::socklen_t = std::mem::size_of_val(&addr) as _;
        // Safety:
        // the socket will outlive the call.
        // addr points to a block of memory of length addr_len
        // addr_len will outlive the call.
        cerr(unsafe { libc::getpeername(self.fd, (&raw mut addr).cast(), &raw mut addr_len) })?;
        Ok(addr)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "sockaddr_in* is always small enough for its size to fit in the destination type."
)]
fn sockaddr_len(addr: sockaddr_storage) -> u32 {
    let len: libc::socklen_t = std::mem::size_of_val(&addr) as _;

    len.min(match addr.ss_family.into() {
        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>() as _,
        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>() as _,
        _ => len,
    })
}

// Generate a control message with T as its contents
// Guarantees that the resulting vec contains valid control messages.
#[expect(
    clippy::cast_possible_truncation,
    reason = "T is always small enough for its size to fit in the destination type."
)]
fn control_message<T>(level: libc::c_int, type_: libc::c_int, content: T) -> Vec<u8> {
    // Safety:
    // libc::CMSG_SPACE is always safe to call.
    let mut control_message = vec![0u8; unsafe { libc::CMSG_SPACE(size_of::<T>() as _) } as _];

    // Safety:
    // libc::CMSG_LEN is always safe to call.
    let mut header = empty_cmsghdr();
    header.cmsg_len = unsafe { libc::CMSG_LEN(size_of::<T>() as _) } as _;
    header.cmsg_level = level;
    header.cmsg_type = type_;

    // Safety:
    // libc::CMSG_SPACE ensures we have sufficient space for the control message header.
    unsafe { write_unaligned(control_message.as_mut_ptr().cast::<libc::cmsghdr>(), header) };

    // Safety:
    // libc::CMSG_SPACE ensures we have sufficient space for the control message contents.
    // libc::CMSG_DATA ensures we write that content at a valid offset.
    // libc::CMSG_DATA provides a valid pointer to the contents of a control message when provided
    // with a valid pointer to a control message header, which we have in the buffer.
    unsafe {
        write_unaligned(
            libc::CMSG_DATA(control_message.as_mut_ptr().cast::<libc::cmsghdr>()).cast::<T>(),
            content,
        );
    };

    control_message
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // Safety: close is always safe to call on a file descriptor
        unsafe { libc::close(self.fd) };
    }
}
