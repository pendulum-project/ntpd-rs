use std::net::Ipv4Addr;

use libc::{in_addr, sockaddr_storage};

use crate::{
    cerr, control_message::empty_msghdr, interface::InterfaceName, raw_socket::sockaddr_len,
};

use super::{control_message, RawSocket};

#[repr(C)]
struct SoTimestamping {
    flags: libc::c_int,
    bind_phc: libc::c_int,
}

impl RawSocket {
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
                libc::IP_PKTINFO,
                &(1 as libc::c_int) as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?;
        }
        Ok(())
    }

    pub(crate) fn so_timestamping(&self, options: u32, bind_phc: u32) -> std::io::Result<()> {
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
        let tstamp_config = SoTimestamping {
            flags: options as libc::c_int,
            bind_phc: bind_phc as libc::c_int,
        };

        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &tstamp_config as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tstamp_config) as libc::socklen_t,
            ))
        }?;
        Ok(())
    }

    pub(crate) fn driver_enable_hardware_timestamping(
        &self,
        interface: InterfaceName,
        rx_filter: libc::c_int,
    ) -> std::io::Result<()> {
        let mut tstamp_config = libc::hwtstamp_config {
            flags: 0,
            tx_type: libc::HWTSTAMP_TX_ON as _,
            rx_filter,
        };

        let mut ifreq = libc::ifreq {
            ifr_name: interface.to_ifr_name(),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_data: (&mut tstamp_config as *mut _) as *mut libc::c_char,
            },
        };

        // Safety:
        // ifreq lives for the duration of the call, ioctl is safe to call otherwise
        cerr(unsafe { libc::ioctl(self.fd, libc::SIOCSHWTSTAMP as _, &mut ifreq) })?;
        Ok(())
    }

    pub(crate) fn bind_to_device(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let value = interface_name.as_str().as_bytes();
        let len = value.len();

        // Safety:
        // value lives for the duration of the call, and is of size len.
        // setsockopt is safe to call in all other regards
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                value.as_ptr().cast(),
                len as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    pub(crate) fn ip_multicast_if(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let request = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_address: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
            },
            imr_ifindex: interface_name
                .get_index()
                .ok_or(std::io::ErrorKind::InvalidInput)? as _,
        };

        // Safety:
        // request lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                &request as *const _ as *const _,
                std::mem::size_of_val(&request) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_multicast_if(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let index = interface_name
            .get_index()
            .ok_or(std::io::ErrorKind::InvalidInput)?;

        // Safety:
        // index lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                &index as *const _ as *const _,
                std::mem::size_of_val(&index) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ip_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };

        // Safety:
        // state lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards.
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_LOOP,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };

        // Safety:
        // state lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards.
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_LOOP,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_v6only(&self, enabled: bool) -> std::io::Result<()> {
        let state: i32 = if enabled { 1 } else { 0 };

        // Safety:
        // state lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards.
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &state as *const _ as *const _,
                std::mem::size_of_val(&state) as _,
            )
        })?;
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
