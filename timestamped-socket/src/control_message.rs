use std::{marker::PhantomData, net::IpAddr};

use crate::socket::Timestamp;

#[cfg(target_os = "linux")]
const SCM_TIMESTAMPING_CMSG_SIZE: usize = control_message_space::<[libc::timespec; 3]>();
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const SCM_TIMESTAMP_NS_CMSG_SIZE: usize = control_message_space::<libc::timespec>();
const SCM_TIMESTAMP_CMSG_SIZE: usize = control_message_space::<libc::timeval>();
#[cfg(target_os = "linux")]
const RECEIVERR_CMSG_SIZE: usize =
    control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();
#[cfg(target_os = "linux")]
const IP_PKTINFO_CMSG_SIZE: usize = control_message_space::<libc::in_pktinfo>();
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
const IP_RECVDSTADDR_CMSG_SIZE: usize = control_message_space::<libc::in_addr>();
const IP6_PKTINFO_CMSG_SIZE: usize = control_message_space::<libc::in6_pktinfo>();

// Utility needed since the ord trait max function is not usable in const environments
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

#[cfg(target_os = "linux")]
pub(crate) const EXPECTED_MAX_CMSG_SIZE: usize =
    max(
        max(SCM_TIMESTAMPING_CMSG_SIZE, SCM_TIMESTAMP_NS_CMSG_SIZE),
        SCM_TIMESTAMP_CMSG_SIZE,
    ) + max(IP_PKTINFO_CMSG_SIZE, IP6_PKTINFO_CMSG_SIZE)
        + RECEIVERR_CMSG_SIZE;
#[cfg(target_os = "freebsd")]
pub(crate) const EXPECTED_MAX_CMSG_SIZE: usize =
    max(SCM_TIMESTAMP_NS_CMSG_SIZE, SCM_TIMESTAMP_CMSG_SIZE)
        + max(IP_RECVDSTADDR_CMSG_SIZE, IP6_PKTINFO_CMSG_SIZE);
#[cfg(target_os = "macos")]
pub(crate) const EXPECTED_MAX_CMSG_SIZE: usize =
    SCM_TIMESTAMP_CMSG_SIZE + max(IP_RECVDSTADDR_CMSG_SIZE, IP6_PKTINFO_CMSG_SIZE);
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
pub(crate) const EXPECTED_MAX_CMSG_SIZE: usize = SCM_TIMESTAMP_CMSG_SIZE + IP6_PKTINFO_CMSG_SIZE;

const fn control_message_space<T>() -> usize {
    // Safety: CMSG_SPACE is safe to call
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

pub(crate) enum MessageQueue {
    Normal,
    #[cfg(target_os = "linux")]
    Error,
}

// Invariants:
// self.mhdr points to a valid libc::msghdr with a valid control
// message region.
// self.next_msg points to one of the control messages
// in the region described by self.mhdr or is NULL
//
// These invariants are guaranteed from the safety conditions on
// calling ControlMessageIterator::new, the fact that next preserves
// these invariants and that the fields of ControlMessageIterator
// are not modified outside these two functions.
pub(crate) struct ControlMessageIterator<'a> {
    mhdr: libc::msghdr,
    next_msg: *const libc::cmsghdr,
    phantom: PhantomData<&'a [u8]>,
}

impl ControlMessageIterator<'_> {
    // Safety assumptions:
    // mhdr has a control and controllen field
    // that together describe a memory region
    // with lifetime 'a containing valid control
    // messages, or MSG_CTRUNC is set.
    pub unsafe fn new(mhdr: libc::msghdr) -> Self {
        // Safety:
        // mhdr's control and controllen fields are valid and point
        // to valid control messages.
        let current_msg = if mhdr.msg_flags & libc::MSG_CTRUNC == 0 {
            unsafe { libc::CMSG_FIRSTHDR(&mhdr) }
        } else {
            std::ptr::null()
        };

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
    Timestamping {
        software: Option<Timestamp>,
        hardware: Option<Timestamp>,
    },
    #[cfg(target_os = "linux")]
    ReceiveError(libc::sock_extended_err),
    DestinationIp(IpAddr),
    Other(libc::cmsghdr),
}

#[cfg(target_os = "linux")]
const SCM_TIMESTAMP_NS: libc::c_int = libc::SCM_TIMESTAMPNS;
#[cfg(target_os = "freebsd")]
const SCM_TIMESTAMP_NS: libc::c_int = libc::SCM_REALTIME;

#[cfg(target_os = "linux")]
const PACKET_TX_TIMESTAMP: libc::c_int = 16;

impl Iterator for ControlMessageIterator<'_> {
    type Item = ControlMessage;

    fn next(&mut self) -> Option<Self::Item> {
        // Safety:
        // By the invariants, self.current_msg either points to a valid control message
        // or is NULL
        let current_msg = unsafe { self.next_msg.as_ref() }?;

        // Safety:
        // Invariants ensure that self.mhdr points to a valid libc::msghdr with a valid
        // control message region, and that self.next_msg either points to a
        // valid control message or is NULL.
        // The previous statement would have returned if self.next_msg were NULL,
        // therefore both passed pointers are valid for use with CMSG_NXTHDR
        // Invariant preservation:
        // CMSG_NXTHDR returns either a pointer to the next valid control message in the
        // control message region described by self.mhdr, or NULL
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

                // Both 0 indicates it is not present
                let hardware = if hardware.tv_sec != 0 || hardware.tv_nsec != 0 {
                    Some(Timestamp::from_timespec(hardware))
                } else {
                    None
                };

                // Both 0 indicates it is not present
                let software = if software.tv_sec != 0 || software.tv_nsec != 0 {
                    Some(Timestamp::from_timespec(software))
                } else {
                    None
                };

                ControlMessage::Timestamping { software, hardware }
            }

            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            (libc::SOL_SOCKET, SCM_TIMESTAMP_NS) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid control message.
                // SO_TIMESTAMPNS always has a timespec in the data
                let cmsg_data = unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timespec;

                let timespec = unsafe { std::ptr::read_unaligned(cmsg_data) };

                ControlMessage::Timestamping {
                    software: Some(Timestamp::from_timespec(timespec)),
                    hardware: None,
                }
            }

            (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid control message.
                // SO_TIMESTAMP always has a timeval in the data
                let cmsg_data = unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timeval;
                let timeval = unsafe { std::ptr::read_unaligned(cmsg_data) };
                ControlMessage::Timestamping {
                    software: Some(Timestamp::from_timeval(timeval)),
                    hardware: None,
                }
            }

            #[cfg(target_os = "linux")]
            (libc::SOL_IP, libc::IP_RECVERR)
            | (libc::SOL_IPV6, libc::IPV6_RECVERR)
            | (libc::SOL_PACKET, PACKET_TX_TIMESTAMP) => {
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

            #[cfg(target_os = "linux")]
            (libc::SOL_IP, libc::IP_PKTINFO) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid
                // control message.
                // IP_PKTINFO always has a in_pktinfo in the data
                let pktinfo = unsafe {
                    let ptr = libc::CMSG_DATA(current_msg) as *const libc::in_pktinfo;
                    std::ptr::read_unaligned(ptr)
                };

                ControlMessage::DestinationIp(
                    std::net::Ipv4Addr::from_bits(u32::from_be(pktinfo.ipi_addr.s_addr)).into(),
                )
            }

            #[cfg(any(target_os = "freebsd", target_os = "macos"))]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid
                // control message.
                // IP_RECVDSTADDR always has a in_addr in the data
                let in_addr = unsafe {
                    let ptr = libc::CMSG_DATA(current_msg) as *const libc::in_addr;
                    std::ptr::read_unaligned(ptr)
                };

                ControlMessage::DestinationIp(
                    std::net::Ipv4Addr::from_bits(u32::from_be(in_addr.s_addr)).into(),
                )
            }

            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // Safety:
                // current_msg was constructed from a pointer that pointed to a valid
                // control message.
                // IPV6_PKTINFO always has a in6_pktinfo in the data
                let pktinfo = unsafe {
                    let ptr = libc::CMSG_DATA(current_msg) as *const libc::in6_pktinfo;
                    std::ptr::read_unaligned(ptr)
                };

                ControlMessage::DestinationIp(
                    std::net::Ipv6Addr::from_bits(u128::from_be_bytes(pktinfo.ipi6_addr.s6_addr))
                        .into(),
                )
            }

            _ => ControlMessage::Other(*current_msg),
        })
    }
}

pub(crate) fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // a zeroed-out sockaddr storage is semantically valid, because a ss_family with
    // value 0 is libc::AF_UNSPEC. Hence the rest of the data does not come with
    // any constraints Safety:
    // the MaybeUninit is zeroed before assumed to be initialized
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}

pub(crate) fn empty_msghdr() -> libc::msghdr {
    // On `target_env = "musl"`, there are several private padding fields.
    // the position of these padding fields depends on the system endianness,
    // so keeping making them public does not really help.
    //
    // Safety:
    //
    // all fields are either integer or pointer types. For those types, 0 is a valid
    // value
    unsafe { std::mem::MaybeUninit::<libc::msghdr>::zeroed().assume_init() }
}

pub(crate) fn empty_cmsghdr() -> libc::cmsghdr {
    // On `target_env = "musl"`, there are several private padding fields.
    // the position of these padding fields depends on the system endianness,
    // so keeping making them public does not really help.
    //
    // Safety:
    //
    // all fields are either integer or pointer types. For those types, 0 is a valid
    // value
    unsafe { std::mem::MaybeUninit::<libc::cmsghdr>::zeroed().assume_init() }
}
