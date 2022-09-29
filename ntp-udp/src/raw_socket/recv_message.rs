use std::os::unix::prelude::AsRawFd;

use super::cerr;

pub(crate) enum MessageQueue {
    Normal,
    Error,
}

/// Receive a message on a socket (retry if interrupted)
pub(crate) fn receive_message(
    socket: &std::net::UdpSocket,
    message_header: &mut libc::msghdr,
    queue: MessageQueue,
) -> std::io::Result<libc::c_int> {
    let receive_flags = match queue {
        MessageQueue::Normal => 0,
        MessageQueue::Error => libc::MSG_ERRQUEUE,
    };

    loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), message_header, receive_flags) } as _)
        {
            Err(e) if std::io::ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => return other,
        }
    }
}

pub(crate) enum ControlMessage {
    Timestamping(libc::timespec),
    ReceiveError(libc::sock_extended_err),
    Other(libc::cmsghdr),
}

pub(crate) fn control_messages(
    message_header: &libc::msghdr,
) -> impl Iterator<Item = ControlMessage> + '_ {
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
pub(crate) const fn control_message_space<T>() -> usize {
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

pub(crate) fn zeroed_sockaddr_storage() -> libc::sockaddr_storage {
    // a zeroed-out sockaddr storage is semantically valid, because a ss_family with value 0 is
    // libc::AF_UNSPEC. Hence the rest of the data does not come with any constraints
    unsafe { std::mem::MaybeUninit::zeroed().assume_init() }
}
