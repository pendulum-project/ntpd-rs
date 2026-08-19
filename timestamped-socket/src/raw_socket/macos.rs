use libc::{in_addr, sockaddr_storage};

use crate::{cerr, control_message::empty_msghdr, raw_socket::sockaddr_len};

use super::{control_message, RawSocket};

impl RawSocket {
    pub(crate) fn so_timestamp(&self, options: u32) -> std::io::Result<()> {
        // Documentation on the timestamping calls:
        //
        // - linux: https://www.kernel.org/doc/Documentation/networking/timestamping.txt
        // - freebsd: https://man.freebsd.org/cgi/man.cgi?setsockopt
        //
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        //
        // Only some bits are valid to set in `options`, but setting invalid bits is
        // perfectly safe
        //
        // > Setting other bit returns EINVAL and does not change the current state.
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }?;

        Ok(())
    }

    pub(crate) fn enable_destination_ipv4(&self) -> std::io::Result<()> {
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_RECVDSTADDR,
                &(1 as libc::c_int) as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    pub(crate) fn send_from_v4(&self, msg: &[u8], addr: in_addr) -> std::io::Result<()> {
        let control_message = control_message(
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: addr,
                ipi_addr: libc::in_addr { s_addr: 0 },
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

    pub(crate) fn send_from_to_v4(
        &self,
        msg: &[u8],
        from: in_addr,
        to: sockaddr_storage,
    ) -> std::io::Result<()> {
        let to_len = sockaddr_len(to);

        let control_message = control_message(
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: from,
                ipi_addr: libc::in_addr { s_addr: 0 },
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
}
