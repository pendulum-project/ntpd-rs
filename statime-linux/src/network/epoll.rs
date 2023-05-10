use std::os::fd::{AsRawFd, RawFd};

use tokio::io::{unix::AsyncFd, Interest};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Could not create epoll fd")]
    CreateError,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ErrqueWaiter {
    epoll_fd: AsyncFd<RawFd>,
}

impl ErrqueWaiter {
    pub fn new(source: &impl AsRawFd) -> Result<Self, Error> {
        // Safety: safe to call with
        let epoll = unsafe { libc::epoll_create(1) };
        if epoll < 0 {
            return Err(Error::CreateError);
        }

        let mut ev = libc::epoll_event {
            events: libc::EPOLLERR as _,
            u64: 0,
        };

        let res = unsafe {
            libc::epoll_ctl(
                epoll,
                libc::EPOLL_CTL_ADD,
                source.as_raw_fd(),
                &mut ev as *mut _,
            )
        };
        if res < 0 {
            return Err(Error::CreateError);
        }

        Ok(Self {
            epoll_fd: AsyncFd::new(epoll)?,
        })
    }

    pub async fn wait(&self) {
        let _ = self
            .epoll_fd
            .async_io(Interest::READABLE, |fd| {
                let mut ev = libc::epoll_event { events: 0, u64: 0 };

                let result = unsafe { libc::epoll_wait(*fd, &mut ev as *mut _, 1, 0) };
                if result == 0 {
                    Err(std::io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(())
                }
            })
            .await;
    }
}
