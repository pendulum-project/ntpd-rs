use std::os::unix::prelude::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use super::cerr;

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
