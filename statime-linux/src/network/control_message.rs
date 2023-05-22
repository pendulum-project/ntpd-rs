use std::marker::PhantomData;

pub const fn control_message_space<T>() -> usize {
    // Safety: CMSG_SPACE is safe to call
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

pub enum MessageQueue {
    Normal,
    Error,
}

// these invariants and that the fields of ControlMessageIterator
// are not modified outside these two functions.
pub struct ControlMessageIterator<'a> {
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
    pub unsafe fn new(mhdr: libc::msghdr) -> Self {
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

pub enum ControlMessage {
    Timestamping(libc::timespec),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

impl<'a> Iterator for ControlMessageIterator<'a> {
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
                // current_msg was constructed from a pointer that pointed to a valid control
                // message. SO_TIMESTAMPING always has 3 timespecs in the data
                let cmsg_data =
                    unsafe { libc::CMSG_DATA(current_msg) } as *const [libc::timespec; 3];

                let [software, _, hardware] = unsafe { std::ptr::read_unaligned(cmsg_data) };

                // if defined, we prefer the hardware over the software timestamp
                let timespec = if hardware.tv_sec != 0 && hardware.tv_nsec != 0 {
                    hardware
                } else {
                    software
                };

                ControlMessage::Timestamping(timespec)
            }

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

pub fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // a zeroed-out sockaddr storage is semantically valid, because a ss_family with
    // value 0 is libc::AF_UNSPEC. Hence the rest of the data does not come with
    // any constraints Safety:
    // the MaybeUninit is zeroed before assumed to be initialized
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}

pub fn empty_msghdr() -> libc::msghdr {
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
