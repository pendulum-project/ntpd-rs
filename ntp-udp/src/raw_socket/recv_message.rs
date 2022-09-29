use std::{io::IoSliceMut, marker::PhantomData, net::SocketAddr, os::unix::prelude::AsRawFd};

use tracing::warn;

use crate::interface_name::sockaddr_storage_to_socket_addr;

use super::cerr;

pub(crate) enum MessageQueue {
    Normal,
    Error,
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

    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: (&mut addr as *mut libc::sockaddr_storage).cast::<libc::c_void>(),
        msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as u32,
    };

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
    // If one of the buffers is too small, recvmsg cuts of data at appropriate boundary
    let sent_bytes = loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, receive_flags) } as _) {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => break other,
        }
    }?;

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

struct ControlMessageIterator<'a> {
    mhdr: libc::msghdr,
    current_msg: *const libc::cmsghdr,
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
        // to control messages.
        let current_msg = unsafe { libc::CMSG_FIRSTHDR(&mhdr) };
        Self {
            mhdr,
            current_msg,
            phantom: PhantomData,
        }
    }
}

pub(crate) enum ControlMessage {
    Timestamping(libc::timespec),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

impl<'a> Iterator for ControlMessageIterator<'a> {
    type Item = ControlMessage;

    fn next(&mut self) -> Option<Self::Item> {
        // Safety:
        // CMSG_FIRSTHDR and CMSG_NXTHDR only return valid pointers or NULL when given valid input
        let current_msg = unsafe { self.current_msg.as_ref() };
        if let Some(current_msg) = current_msg {
            // Safety:
            // New ensure mhdr is valid
            // CMSG_FIRSTHDR and CMSG_NXTHDR only return valid pointers or NULL when given valid input
            self.current_msg = unsafe { libc::CMSG_NXTHDR(&self.mhdr, self.current_msg) };

            match (current_msg.cmsg_level, current_msg.cmsg_type) {
                (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) => {
                    // Safety:
                    // New ensures we have valid control messages
                    // SO_TIMESTAMPING always has a timespec in the data
                    let cmsg_data =
                        unsafe { libc::CMSG_DATA(current_msg) } as *const libc::timespec;
                    let timespec = unsafe { std::ptr::read_unaligned(cmsg_data) };
                    Some(ControlMessage::Timestamping(timespec))
                }

                (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                    // this is part of how timestamps are reported.
                    // Safety:
                    // New ensures we have valid control messages
                    // IP*_RECVERR always has a sock_extended_err in the data
                    let error = unsafe {
                        let ptr = libc::CMSG_DATA(current_msg) as *const libc::sock_extended_err;
                        std::ptr::read_unaligned(ptr)
                    };

                    Some(ControlMessage::ReceiveError(error))
                }
                _ => Some(ControlMessage::Other(*current_msg)),
            }
        } else {
            None
        }
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
