use std::os::unix::prelude::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use super::cerr;

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
