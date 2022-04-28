use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    os::unix::prelude::AsRawFd,
};

use ntp_proto::NtpTimestamp;
use tokio::io::unix::AsyncFd;

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;
        init_socket(&socket)?;
        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
        })
    }

    pub fn from_tokio(socket: tokio::net::UdpSocket) -> io::Result<UdpSocket> {
        // tokio sockets are already non-blocking
        let socket = socket.into_std()?;
        init_socket(&socket)?;
        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
        })
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv(
        &self,
        buf: &mut [u8],
        recv_ts: &mut Option<NtpTimestamp>,
    ) -> io::Result<usize> {
        loop {
            let mut guard = self.io.readable().await?;
            match guard.try_io(|inner| recv(inner.get_ref(), buf, recv_ts)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn init_socket(socket: &std::net::UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enable_ts: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS_NEW,
            &enable_ts as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    Ok(())
}

fn recv(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
    recv_ts: &mut Option<NtpTimestamp>,
) -> io::Result<usize> {
    let mut buf_slice = IoSliceMut::new(buf);

    // could be on the stack if const extern fn is stable
    let control_size =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::timespec>() as _) } as usize;
    let mut control_buf = vec![0; control_size];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: buf_slice.as_mut_ptr().cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
    };

    // loops for when we receive an interrupt during the recv
    let n = loop {
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut mhdr, 0) };

        if n == -1 {
            let e = io::Error::last_os_error();

            if let ErrorKind::Interrupted = e.kind() {
                // retry when the recv was interrupted
                continue;
            }

            return Err(e);
        }
        break n;
    };

    // Loops through the control messages, but we should only get a single message
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&mhdr).as_ref() };
    while let Some(msg) = cmsg {
        if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS_NEW) = (msg.cmsg_level, msg.cmsg_type) {
            // Safety: SCM_TIMESTAMPNS always has a timespec in the data, so this operation should be safe
            let ts: libc::timespec =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(msg) as *const _) };
            *recv_ts = Some(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                ts.tv_sec as u32,  // truncates the higher bits of the i64
                ts.tv_nsec as u32, // tv_nsec is always within [0, 1e10)
            ));
            break;
        }

        // grab the next control message
        cmsg = unsafe { libc::CMSG_NXTHDR(&mhdr, msg).as_ref() };
    }

    Ok(n as usize)
}
