use std::{
    io::IoSliceMut,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, RawFd},
};

use super::{
    cerr,
    control_message::{
        empty_msghdr, zeroed_sockaddr_storage, ControlMessage, ControlMessageIterator, MessageQueue,
    },
    interface::{sockaddr_storage_to_socket_addr, InterfaceName},
    linux::TimestampingMode,
};

pub(crate) use exceptional_condition_fd::exceptional_condition_fd;
pub(crate) use set_timestamping_options::set_timestamping_options;

pub struct RawUdpSocket(RawFd);

impl RawUdpSocket {
    pub fn new_into_std(
        socket_addr: SocketAddr,
        interface_name: Option<InterfaceName>,
    ) -> std::io::Result<std::net::UdpSocket> {
        let socket = Self::new(socket_addr)?;

        // it is important to configure `reuse_addr` before binding.
        // not doing so causes startup problems for boundary clocks.
        socket.reuse_addr()?;

        socket.bind(socket_addr)?;
        socket.set_nonblocking(true)?;

        if let Some(interface_name) = interface_name {
            // empty string does not work, `bind_to_device` should be skipped instead
            debug_assert!(!interface_name.as_str().is_empty());

            socket.bind_to_device(interface_name)?;
        }

        Ok(unsafe { std::net::UdpSocket::from_raw_fd(socket.0) })
    }

    fn new(socket_addr: SocketAddr) -> std::io::Result<Self> {
        let fd = cerr(unsafe {
            libc::socket(
                match socket_addr {
                    SocketAddr::V4(_) => libc::AF_INET,
                    SocketAddr::V6(_) => libc::AF_INET6,
                },
                libc::SOCK_DGRAM,
                libc::IPPROTO_UDP,
            )
        })?;

        Ok(Self(fd))
    }

    fn reuse_addr(&self) -> std::io::Result<()> {
        let options = 1u32;

        // Safety:
        //
        // the pointer argument is valid, the size is accurate
        unsafe {
            cerr(libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    fn bind(&self, socket_addr: SocketAddr) -> std::io::Result<()> {
        match socket_addr {
            SocketAddr::V4(addr) => {
                let sockaddr_in = libc::sockaddr_in {
                    sin_family: libc::AF_INET as _,
                    sin_port: u16::from_ne_bytes(addr.port().to_be_bytes()),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(addr.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };

                let address = &sockaddr_in as *const _ as *const libc::sockaddr;
                let address_len = std::mem::size_of_val(&sockaddr_in) as libc::socklen_t;

                cerr(unsafe { libc::bind(self.0, address, address_len) })?;

                Ok(())
            }
            SocketAddr::V6(addr) => {
                let sockaddr_in6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as _,
                    sin6_port: u16::from_ne_bytes(addr.port().to_be_bytes()),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: addr.scope_id(),
                };

                let address = &sockaddr_in6 as *const _ as *const libc::sockaddr;
                let address_len = std::mem::size_of_val(&sockaddr_in6) as libc::socklen_t;

                cerr(unsafe { libc::bind(self.0, address, address_len) })?;

                Ok(())
            }
        }
    }

    fn bind_to_device(&self, interface_name: InterfaceName) -> std::io::Result<()> {
        let value = interface_name.as_str().as_bytes();
        let len = value.len();

        unsafe {
            cerr(libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                value.as_ptr().cast(),
                len as libc::socklen_t,
            ))?;
        }

        Ok(())
    }

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        let nonblocking = nonblocking as libc::c_int;
        cerr(unsafe { libc::ioctl(self.0, libc::FIONBIO, &nonblocking) }).map(drop)
    }
}

pub fn receive_message<'a>(
    socket: &std::net::UdpSocket,
    packet_buf: &mut [u8],
    control_buf: &'a mut [u8],
    queue: MessageQueue,
) -> std::io::Result<(
    usize,
    impl Iterator<Item = ControlMessage> + 'a,
    Option<SocketAddr>,
)> {
    let mut buf_slice = IoSliceMut::new(packet_buf);
    let mut addr = zeroed_sockaddr_storage();

    let mut mhdr = empty_msghdr();

    mhdr.msg_control = control_buf.as_mut_ptr().cast::<libc::c_void>();
    mhdr.msg_controllen = control_buf.len() as _;
    mhdr.msg_iov = (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>();
    mhdr.msg_iovlen = 1;
    mhdr.msg_flags = 0;
    mhdr.msg_name = (&mut addr as *mut libc::sockaddr_storage).cast::<libc::c_void>();
    mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;

    let receive_flags = match queue {
        MessageQueue::Normal => 0,
        MessageQueue::Error => libc::MSG_ERRQUEUE,
    };

    // Safety:
    // We have a mutable reference to the control buffer for the duration of the
    // call, and controllen is also set to it's length.
    // IoSliceMut is ABI compatible with iovec, and we only have 1 which matches iovlen
    // msg_name is initialized to point to an owned sockaddr_storage and
    // msg_namelen is the size of sockaddr_storage
    // If one of the buffers is too small, recvmsg cuts off data at appropriate boundary
    let sent_bytes = loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, receive_flags) } as _) {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }
            Err(e) => return Err(e),
            Ok(sent) => break sent as usize,
        }
    };

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        log::warn!(
            "truncated packet because it was larger than expected: {} bytes",
            packet_buf.len(),
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        log::warn!("truncated control messages");
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
        sent_bytes,
        unsafe { ControlMessageIterator::new(mhdr) },
        sockaddr_storage_to_socket_addr(&addr),
    ))
}

mod set_timestamping_options {
    use std::os::unix::prelude::AsRawFd;

    use super::{cerr, TimestampingMode};
    use crate::network::interface::InterfaceName;

    fn configure_timestamping_socket(
        udp_socket: &std::net::UdpSocket,
        options: u32,
    ) -> std::io::Result<libc::c_int> {
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
        // Only some bits are valid to set in `options`, but setting invalid bits is perfectly safe
        //
        // > Setting other bit returns EINVAL and does not change the current state.
        unsafe {
            cerr(libc::setsockopt(
                udp_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }
    }

    pub(crate) fn set_timestamping_options(
        udp_socket: &std::net::UdpSocket,
        timestamping_mode: TimestampingMode,
    ) -> std::io::Result<()> {
        // Setup timestamping
        let options = match timestamping_mode {
            TimestampingMode::Hardware(interface_name) => {
                // must explicitly enable hardware timestamping
                driver_enable_hardware_timestamping(udp_socket, interface_name);

                libc::SOF_TIMESTAMPING_RAW_HARDWARE
                    | libc::SOF_TIMESTAMPING_RX_HARDWARE
                    | libc::SOF_TIMESTAMPING_TX_HARDWARE
                    | libc::SOF_TIMESTAMPING_OPT_TSONLY
                    | libc::SOF_TIMESTAMPING_OPT_ID
            }
            TimestampingMode::Software => {
                libc::SOF_TIMESTAMPING_SOFTWARE
                    | libc::SOF_TIMESTAMPING_RX_SOFTWARE
                    | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                    | libc::SOF_TIMESTAMPING_OPT_TSONLY
                    | libc::SOF_TIMESTAMPING_OPT_ID
            }
        };

        configure_timestamping_socket(udp_socket, options)?;

        Ok(())
    }

    pub fn driver_enable_hardware_timestamping(
        udp_socket: &std::net::UdpSocket,
        interface: InterfaceName,
    ) {
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

        let fd = udp_socket.as_raw_fd();
        cerr(unsafe { libc::ioctl(fd, libc::SIOCGHWTSTAMP as _, &mut ifreq) })
            .expect("Failed to enable hardware timestamping in the driver");
    }
}

mod exceptional_condition_fd {
    use std::os::unix::prelude::{AsRawFd, RawFd};

    use tokio::io::unix::AsyncFd;

    use super::cerr;

    // Tokio does not natively support polling for readiness of queues
    // other than the normal read queue (see also https://github.com/tokio-rs/tokio/issues/4885)
    // this works around that by creating a epoll fd that becomes
    // ready to read when the underlying fd has an event on its error queue.
    pub(crate) fn exceptional_condition_fd(
        socket_of_interest: &std::net::UdpSocket,
    ) -> std::io::Result<AsyncFd<RawFd>> {
        // Safety:
        // epoll_create1 is safe to call without flags
        let fd = cerr(unsafe { libc::epoll_create1(0) })?;

        let mut event = libc::epoll_event {
            events: libc::EPOLLPRI as u32,
            u64: 0u64,
        };

        // Safety:
        // fd is a valid epoll fd from epoll_create1 in combination with the cerr check
        // since we have a reference to the socket_of_interest, its raw fd
        // is valid for the duration of this call, which is all that is
        // required for epoll (closing the fd later is safe!)
        // &mut event is a pointer to a memory region which we own for the duration
        // of the call, and thus ok to use.
        cerr(unsafe {
            libc::epoll_ctl(
                fd,
                libc::EPOLL_CTL_ADD,
                socket_of_interest.as_raw_fd(),
                &mut event,
            )
        })?;

        AsyncFd::new(fd)
    }
}
