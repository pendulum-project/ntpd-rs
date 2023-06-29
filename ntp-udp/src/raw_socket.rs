/// This file contains safe wrappers for the socket-related system calls
/// needed to implement the UdpSocket in socket.rs
///
/// Since the safety of a rust unsafe block depends not only on its
/// contents, but also the context within which it is called, the code
/// here is split up in submodules that are individually as small as
/// possible while still having each a fully safe API interface. This
/// should reduce the amount of context which needs to be considered
/// when reasoning about safety, significantly simplifying the checking
/// of this code.
///
/// All unsafe blocks are preceded with a comment explaining why that
/// specific unsafe code should be safe within the context in which it
/// is used.
pub(crate) use recv_message::{
    control_message_space, receive_message, ControlMessage, MessageQueue,
};
pub(crate) use set_timestamping_options::set_timestamping_options;

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(i32)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum TimestampMethod {
    /// Original timestamping for unix (linux, freebsd, macos)
    ///
    /// - microsecond precision (on freebsd, can be configured to get nanoseconds)
    /// - only receive timestamps
    #[allow(dead_code)]
    SoTimestamp = libc::SO_TIMESTAMP,
    /// Standard timestamping on linux. It gives us
    ///
    /// - nanosecond precision
    /// - send & receive timestamps
    #[cfg(target_os = "linux")]
    SoTimestamping = libc::SO_TIMESTAMPING,
    /// Legacy timestamping for linux
    ///
    /// - nanosecond precision
    /// - only receive timestamps
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    SoTimestampns = libc::SO_TIMESTAMPNS,
}

mod set_timestamping_options {
    use std::os::unix::prelude::AsRawFd;

    use crate::EnableTimestamps;

    use super::{cerr, TimestampMethod};

    enum SockOpt {
        Method(TimestampMethod),
        #[cfg(target_os = "freebsd")]
        Clock,
    }

    fn configure_timestamping_socket(
        udp_socket: &std::net::UdpSocket,
        option: SockOpt,
        value: u32,
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
                match option {
                    SockOpt::Method(m) => m as i32 as libc::c_int,
                    #[cfg(target_os = "freebsd")]
                    SockOpt::Clock => libc::SO_TS_CLOCK,
                },
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            ))
        }
    }

    pub(crate) fn set_timestamping_options(
        udp_socket: &std::net::UdpSocket,
        method: TimestampMethod,
        timestamping: EnableTimestamps,
    ) -> std::io::Result<()> {
        let options = match method {
            TimestampMethod::SoTimestamp => {
                // only receive software timestamps are supported: 0 disables, 1 enables
                timestamping.rx_software as u32
            }
            #[cfg(target_os = "linux")]
            TimestampMethod::SoTimestampns => {
                // only receive software timestamps are supported: 0 disables, 1 enables
                timestamping.rx_software as u32
            }
            #[cfg(target_os = "linux")]
            TimestampMethod::SoTimestamping => {
                // SO_TIMESTAMPING has many more options: it supports receive and send timestamps, and
                // software and hardware timestamping. Of those, only software send and receive timestamps
                // are currently supported
                let mut options = 0;

                if timestamping.rx_software || timestamping.tx_software {
                    // enable software timestamping
                    options |= libc::SOF_TIMESTAMPING_SOFTWARE
                }

                if timestamping.rx_software {
                    // we want receive timestamps
                    options |= libc::SOF_TIMESTAMPING_RX_SOFTWARE
                }

                if timestamping.tx_software {
                    // - we want send timestamps
                    // - return just the timestamp, don't send the full message along
                    // - tag the timestamp with an ID
                    options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE
                        | libc::SOF_TIMESTAMPING_OPT_TSONLY
                        | libc::SOF_TIMESTAMPING_OPT_ID;
                }

                if timestamping.rx_hardware || timestamping.tx_hardware {
                    // enable hardware timestamping
                    options |= libc::SOF_TIMESTAMPING_RAW_HARDWARE;

                    #[cfg(target_os = "linux")]
                    crate::hwtimestamp::driver_enable_hardware_timestamping(udp_socket)?;
                }

                if timestamping.rx_hardware {
                    options |= libc::SOF_TIMESTAMPING_RX_HARDWARE;
                }

                if timestamping.tx_hardware {
                    options |= libc::SOF_TIMESTAMPING_TX_HARDWARE
                        | libc::SOF_TIMESTAMPING_OPT_TSONLY
                        | libc::SOF_TIMESTAMPING_OPT_ID;

                    // in practice, this is needed to have `SOF_TIMESTAMPING_OPT_ID` work
                    // without it, the reported id is always 0.
                    options |= libc::SOF_TIMESTAMPING_TX_SOFTWARE;
                }

                options
            }
        };

        configure_timestamping_socket(udp_socket, SockOpt::Method(method), options)?;

        #[cfg(target_os = "freebsd")]
        configure_timestamping_socket(udp_socket, SockOpt::Clock, libc::SO_TS_REALTIME as u32)?;

        Ok(())
    }
}

mod recv_message {
    use std::{
        io::IoSliceMut, marker::PhantomData, mem::MaybeUninit, net::SocketAddr,
        os::unix::prelude::AsRawFd,
    };

    use tracing::warn;

    use crate::interface::sockaddr_storage_to_socket_addr;
    use crate::LibcTimestamp;

    use super::cerr;

    pub(crate) enum MessageQueue {
        Normal,
        #[cfg(target_os = "linux")]
        Error,
    }

    fn empty_msghdr() -> libc::msghdr {
        // On `target_env = "musl"`, there are several private padding fields.
        // the position of these padding fields depends on the system endianness,
        // so keeping making them public does not really help.
        //
        // Safety:
        //
        // all fields are either integer or pointer types. For those types, 0 is a valid value
        unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() }
    }

    pub(crate) fn receive_message<'a>(
        socket: &std::net::UdpSocket,
        packet_buf: &mut [u8],
        control_buf: &'a mut [u8],
        queue: MessageQueue,
    ) -> std::io::Result<(
        libc::c_int,
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
            #[cfg(target_os = "linux")]
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
            match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, receive_flags) } as _)
            {
                Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                    // retry when the recv was interrupted
                    continue;
                }
                Err(e) => return Err(e),
                Ok(sent) => break sent,
            }
        };

        if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
            warn!(
                max_len = packet_buf.len(),
                "truncated packet because it was larger than expected",
            );
        }

        if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
            warn!("truncated control messages");
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

    // Invariants:
    // self.mhdr points to a valid libc::msghdr with a valid control
    // message region.
    // self.current_msg points to one of the control messages
    // in the region described by self.mhdr or is NULL
    //
    // These invariants are guaranteed from the safety conditions on
    // calling ControlMessageIterator::new, the fact that next preserves
    // these invariants and that the fields of ControlMessageIterator
    // are not modified outside these two functions.
    struct ControlMessageIterator<'a> {
        mhdr: libc::msghdr,
        next_msg: *const libc::cmsghdr,
        phantom: PhantomData<&'a [u8]>,
    }

    impl<'a> ControlMessageIterator<'a> {
        // Safety assumptions:
        // mhdr has a control and controllen field
        // that together describe a memory region
        // with lifetime 'a containing valid control
        // messages
        unsafe fn new(mhdr: libc::msghdr) -> Self {
            // Safety:
            // mhdr's control and controllen fields are valid and point
            // to valid control messages.
            let current_msg = unsafe { libc::CMSG_FIRSTHDR(&mhdr) };

            // Invariant preservation:
            // The safety assumptions guaranteed by the caller ensure
            // that mhdr points to a valid region with valid control
            // messages. CMSG_FIRSTHDR is then guaranteed to either
            // return the pointer to the first valid control message
            // in that region, or NULL if the region is empty.
            Self {
                mhdr,
                next_msg: current_msg,
                phantom: PhantomData,
            }
        }
    }

    pub(crate) enum ControlMessage {
        Timestamping(crate::LibcTimestamp),
        #[cfg(target_os = "linux")]
        ReceiveError(libc::sock_extended_err),
        Other(libc::cmsghdr),
    }

    #[cfg(target_os = "linux")]
    const SCM_TIMESTAMP_NS: libc::c_int = libc::SCM_TIMESTAMPNS;
    #[cfg(target_os = "freebsd")]
    const SCM_TIMESTAMP_NS: libc::c_int = libc::SCM_REALTIME;

    impl<'a> Iterator for ControlMessageIterator<'a> {
        type Item = ControlMessage;

        fn next(&mut self) -> Option<Self::Item> {
            // Safety:
            // By the invariants, self.current_msg either points to a valid control message
            // or is NULL
            let current_msg = unsafe { self.next_msg.as_ref() }?;

            // Safety:
            // Invariants ensure that self.mhdr points to a valid libc::msghdr with a valid control
            // message region, and that self.next_msg either points to a valid control message
            // or is NULL.
            // The previous statement would have returned if self.next_msg were NULL, therefore both passed
            // pointers are valid for use with CMSG_NXTHDR
            // Invariant preservation:
            // CMSG_NXTHDR returns either a pointer to the next valid control message in the control
            // message region described by self.mhdr, or NULL
            self.next_msg = unsafe { libc::CMSG_NXTHDR(&self.mhdr, self.next_msg) };

            Some(match (current_msg.cmsg_level, current_msg.cmsg_type) {
                #[cfg(target_os = "linux")]
                (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => {
                    // Safety:
                    // current_msg was constructed from a pointer that pointed to a valid control message.
                    // SO_TIMESTAMPING always has 3 timespecs in the data
                    let cmsg_data =
                        unsafe { libc::CMSG_DATA(current_msg) } as *const [libc::timespec; 3];

                    let [software, _, hardware] = unsafe { std::ptr::read_unaligned(cmsg_data) };

                    // if defined, we prefer the hardware over the software timestamp
                    let timespec = if hardware.tv_sec != 0 && hardware.tv_nsec != 0 {
                        hardware
                    } else {
                        software
                    };

                    ControlMessage::Timestamping(LibcTimestamp::from_timespec(timespec))
                }

                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                (libc::SOL_SOCKET, SCM_TIMESTAMP_NS) => {
                    // Safety:
                    // current_msg was constructed from a pointer that pointed to a valid control message.
                    // SO_TIMESTAMPNS always has a timespec in the data
                    let cmsg_data =
                        unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timespec;

                    let timespec = unsafe { std::ptr::read_unaligned(cmsg_data) };

                    ControlMessage::Timestamping(LibcTimestamp::from_timespec(timespec))
                }

                (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
                    // Safety:
                    // current_msg was constructed from a pointer that pointed to a valid control message.
                    // SO_TIMESTAMP always has a timeval in the data
                    let cmsg_data = unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timeval;
                    let timeval = unsafe { std::ptr::read_unaligned(cmsg_data) };
                    ControlMessage::Timestamping(LibcTimestamp::from_timeval(timeval))
                }

                #[cfg(target_os = "linux")]
                (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                    // this is part of how timestamps are reported.
                    // Safety:
                    // current_msg was constructed from a pointer that pointed to a valid
                    // control message.
                    // IP*_RECVERR always has a sock_extended_err in the data
                    let error = unsafe {
                        let ptr = libc::CMSG_DATA(current_msg) as *const libc::sock_extended_err;
                        std::ptr::read_unaligned(ptr)
                    };

                    ControlMessage::ReceiveError(error)
                }
                _ => ControlMessage::Other(*current_msg),
            })
        }
    }

    /// The space used to store a control message that contains a value of type T
    pub(crate) const fn control_message_space<T>() -> usize {
        // Safety: CMSG_SPACE is safe to call
        (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
    }

    fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
        // a zeroed-out sockaddr storage is semantically valid, because a ss_family with value 0 is
        // libc::AF_UNSPEC. Hence the rest of the data does not come with any constraints
        // Safety:
        // the MaybeUninit is zeroed before assumed to be initialized
        unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
    }
}

#[allow(unused)]
#[cfg(target_os = "linux")]
pub(crate) mod timestamping_config {
    use std::os::fd::RawFd;

    use crate::interface::InterfaceName;

    #[repr(C)]
    #[allow(non_camel_case_types)]
    #[derive(Default)]
    struct ethtool_ts_info {
        cmd: u32,
        so_timestamping: u32,
        phc_index: i32,
        tx_types: u32,
        tx_reserved: [u32; 3],
        rx_filters: u32,
        rx_reserved: [u32; 3],
    }

    #[derive(Debug, Clone, Copy)]
    struct TimestampSupport {
        rx_software: bool,
        tx_software: bool,
        rx_hardware: bool,
        tx_hardware: bool,
        #[cfg(test)]
        phc_index: Option<u32>,
    }

    impl TimestampSupport {
        fn for_interface(interface_name: InterfaceName) -> std::io::Result<Self> {
            let socket = super::cerr(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) })?;

            let value = interface_name.as_str().as_bytes();
            let len = value.len();

            unsafe {
                super::cerr(libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    value.as_ptr().cast(),
                    len as libc::socklen_t,
                ))?;
            }

            Self::for_socket(socket, interface_name)
        }

        #[cfg(target_os = "linux")]
        fn for_socket(socket: RawFd, interface_name: InterfaceName) -> std::io::Result<Self> {
            // Get time stamping and PHC info
            const ETHTOOL_GET_TS_INFO: u32 = 0x00000041;

            let mut tsi: ethtool_ts_info = ethtool_ts_info {
                cmd: ETHTOOL_GET_TS_INFO,
                ..Default::default()
            };

            let ifr: libc::ifreq = libc::ifreq {
                ifr_name: interface_name.to_ifr_name(),
                ifr_ifru: libc::__c_anonymous_ifr_ifru {
                    ifru_data: (&mut tsi as *mut _) as *mut libc::c_char,
                },
            };

            // SIOCETHTOOL = 0x8946 (Ethtool interface) Linux ioctl request
            super::cerr(unsafe { libc::ioctl(socket, 0x8946, &ifr) })?;

            let support = Self {
                rx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_RX_SOFTWARE != 0,
                tx_software: tsi.so_timestamping & libc::SOF_TIMESTAMPING_TX_SOFTWARE != 0,
                rx_hardware: tsi.so_timestamping & libc::SOF_TIMESTAMPING_RX_HARDWARE != 0,
                tx_hardware: tsi.so_timestamping & libc::SOF_TIMESTAMPING_TX_HARDWARE != 0,
                #[cfg(test)]
                phc_index: u32::try_from(tsi.phc_index).ok(),
            };

            Ok(support)
        }

        #[cfg(test)]
        fn phc_clock_pathbuf(&self) -> Option<std::path::PathBuf> {
            use std::path::PathBuf;

            self.phc_index
                .map(|index| PathBuf::from(format!("/dev/ptp{index}")))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn loopback_timestamping_support() {
            let support = TimestampSupport::for_interface(InterfaceName::LOOPBACK).unwrap();

            assert!(support.rx_software);
            assert!(support.tx_software);

            assert!(!support.rx_hardware);
            assert!(!support.tx_hardware);

            assert!(support.phc_clock_pathbuf().is_none());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod err_queue_waiter {

    use std::os::unix::prelude::{AsRawFd, RawFd};

    use tokio::io::{unix::AsyncFd, Interest};

    use crate::raw_socket::cerr;

    pub struct ErrQueueWaiter {
        epoll_fd: AsyncFd<RawFd>,
    }

    fn create_error(inner: std::io::Error) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("could not create error queue waiter epoll socket: {inner:?}"),
        )
    }

    impl ErrQueueWaiter {
        pub fn new(source: &impl AsRawFd) -> std::io::Result<Self> {
            // Safety: safe to call with
            let epoll = cerr(unsafe { libc::epoll_create(1) }).map_err(create_error)?;

            let mut ev = libc::epoll_event {
                events: libc::EPOLLERR as _,
                u64: 0,
            };

            cerr(unsafe {
                libc::epoll_ctl(
                    epoll,
                    libc::EPOLL_CTL_ADD,
                    source.as_raw_fd(),
                    &mut ev as *mut _,
                )
            })
            .map_err(create_error)?;

            Ok(Self {
                epoll_fd: AsyncFd::new(epoll)?,
            })
        }

        pub async fn wait(&self) -> std::io::Result<()> {
            self.epoll_fd
                .async_io(Interest::READABLE, |fd| {
                    let mut ev = libc::epoll_event { events: 0, u64: 0 };

                    match unsafe { libc::epoll_wait(*fd, &mut ev as *mut _, 1, 0) } {
                        0 => Err(std::io::ErrorKind::WouldBlock.into()),
                        _ => Ok(()),
                    }
                })
                .await
        }
    }
}

pub(crate) mod interface_iterator {
    use crate::interface::{sockaddr_to_socket_addr, InterfaceData, InterfaceName};
    use std::str::FromStr;

    pub struct InterfaceIterator {
        base: *mut libc::ifaddrs,
        next: *mut libc::ifaddrs,
    }

    impl InterfaceIterator {
        pub fn new() -> std::io::Result<Self> {
            let mut addrs = core::mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();

            unsafe {
                super::cerr(libc::getifaddrs(addrs.as_mut_ptr()))?;

                Ok(Self {
                    base: addrs.assume_init(),
                    next: addrs.assume_init(),
                })
            }
        }
    }

    impl Drop for InterfaceIterator {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.base) };
        }
    }

    impl Iterator for InterfaceIterator {
        type Item = InterfaceData;

        fn next(&mut self) -> Option<<Self as Iterator>::Item> {
            let ifaddr = unsafe { self.next.as_ref() }?;

            self.next = ifaddr.ifa_next;

            let ifname = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) };
            let name = match std::str::from_utf8(ifname.to_bytes()) {
                Err(_) => unreachable!("interface names must be ascii"),
                Ok(name) => InterfaceName::from_str(name).expect("name from os"),
            };

            let family = unsafe { (*ifaddr.ifa_addr).sa_family };

            let mac = if family as i32 == libc::AF_PACKET {
                let sockaddr_ll: libc::sockaddr_ll =
                    unsafe { std::ptr::read_unaligned(ifaddr.ifa_addr as *const _) };

                Some([
                    sockaddr_ll.sll_addr[0],
                    sockaddr_ll.sll_addr[1],
                    sockaddr_ll.sll_addr[2],
                    sockaddr_ll.sll_addr[3],
                    sockaddr_ll.sll_addr[4],
                    sockaddr_ll.sll_addr[5],
                ])
            } else {
                None
            };

            let socket_addr = unsafe { sockaddr_to_socket_addr(ifaddr.ifa_addr) };

            let data = InterfaceData {
                name,
                mac,
                socket_addr,
            };

            Some(data)
        }
    }
}
