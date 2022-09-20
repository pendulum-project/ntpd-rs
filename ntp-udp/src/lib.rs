mod interface_name;
mod socket;

pub use socket::UdpSocket;
use std::os::unix::prelude::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

fn set_timestamping_options(
    udp_socket: &std::net::UdpSocket,
    timestamping: TimestampingConfig,
) -> std::io::Result<()> {
    let fd = udp_socket.as_raw_fd();

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

    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ))?
    };

    Ok(())
}

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

/// Receive a message on a socket (retry if interrupted)
fn receive_message(
    socket: &std::net::UdpSocket,
    message_header: &mut libc::msghdr,
    flags: libc::c_int,
) -> std::io::Result<libc::c_int> {
    loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), message_header, flags) } as _) {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => return other,
        }
    }
}

enum ControlMessage {
    Timestamping(libc::timespec),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

fn control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = ControlMessage> + '_ {
    raw_control_messages(message_header).map(|msg| match (msg.cmsg_level, msg.cmsg_type) {
        (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) => {
            // Safety: SO_TIMESTAMPING always has a timespec in the data
            let cmsg_data = unsafe { libc::CMSG_DATA(msg) } as *const libc::timespec;
            let timespec = unsafe { std::ptr::read_unaligned(cmsg_data) };
            ControlMessage::Timestamping(timespec)
        }

        (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
            // this is part of how timestamps are reported.
            let error = unsafe {
                let ptr = libc::CMSG_DATA(msg) as *const libc::sock_extended_err;
                std::ptr::read_unaligned(ptr)
            };

            ControlMessage::ReceiveError(error)
        }
        _ => ControlMessage::Other(*msg),
    })
}

fn raw_control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = &libc::cmsghdr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message_header).as_ref() };

    std::iter::from_fn(move || match cmsg {
        None => None,
        Some(current) => {
            cmsg = unsafe { libc::CMSG_NXTHDR(message_header, current).as_ref() };

            Some(current)
        }
    })
}

/// The space used to store a control message that contains a value of type T
const fn control_message_space<T>() -> usize {
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

pub(crate) fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // a zeroed-out sockaddr storage is semantically valid, because a ss_family with value 0 is
    // libc::AF_UNSPEC. Hence the rest of the data does not come with any constraints
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TimestampingConfig {
    rx_software: bool,
    tx_software: bool,
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
    fn all_supported(udp_socket: &std::net::UdpSocket) -> std::io::Result<Self> {
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

pub(crate) fn exceptional_condition_fd(
    socket_of_interest: &std::net::UdpSocket,
) -> std::io::Result<AsyncFd<RawFd>> {
    let fd = cerr(unsafe { libc::epoll_create1(0) })?;

    let mut event = libc::epoll_event {
        events: libc::EPOLLPRI as u32,
        u64: 0u64,
    };

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
