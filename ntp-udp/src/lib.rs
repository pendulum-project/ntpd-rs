use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    os::unix::prelude::AsRawFd,
};

use log::{debug, trace, warn};
use ntp_proto::NtpTimestamp;
use tokio::{io::unix::AsyncFd, net::ToSocketAddrs};

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
}

impl UdpSocket {
    pub async fn new<A: ToSocketAddrs, B: ToSocketAddrs>(
        listen_addr: A,
        target_addr: B,
    ) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!("socket bound to local address {:?}", socket.local_addr());
        socket.connect(target_addr).await?;
        debug!(
            "socket bound to {:?} connected to peer address {:?}",
            socket.local_addr(),
            socket.peer_addr()
        );
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
                Ok(result) => {
                    if log::log_enabled!(log::Level::Debug) {
                        if let Err(e) = &result {
                            debug!("error sending data: {}", e);
                        }
                    }

                    if log::log_enabled!(log::Level::Trace) {
                        if let Ok(size) = &result {
                            trace!(
                                "sent {} bytes from {:?} to peer {:?}",
                                size,
                                self.as_ref().local_addr(),
                                self.as_ref().peer_addr()
                            );
                        }
                    }

                    return result;
                }
                Err(_would_block) => {
                    trace!(
                        "socket {:?} was blocked after becoming writable, retrying",
                        self.as_ref().local_addr()
                    );
                    continue;
                }
            }
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        loop {
            let mut guard = self.io.readable().await?;
            match guard.try_io(|inner| recv(inner.get_ref(), buf)) {
                Ok(result) => {
                    if log::log_enabled!(log::Level::Debug) {
                        if let Err(e) = &result {
                            debug!("error receiving data: {}", e);
                        }
                    }

                    if log::log_enabled!(log::Level::Trace) {
                        if let Ok((size, ts)) = &result {
                            trace!(
                                "received message of size {} with receive ts {:?} from {:?}",
                                size,
                                ts,
                                self.as_ref().local_addr()
                            );
                        }
                    }
                    return result;
                }
                Err(_would_block) => {
                    trace!(
                        "socket {:?} was blocked after becoming readable, retrying",
                        self.as_ref().local_addr()
                    );
                    continue;
                }
            }
        }
    }
}

impl AsRef<std::net::UdpSocket> for UdpSocket {
    fn as_ref(&self) -> &std::net::UdpSocket {
        self.io.get_ref()
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

fn recv(socket: &std::net::UdpSocket, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    // could be on the stack if const extern fn is stable
    let control_size =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::timespec>() as _) } as usize;
    let mut control_buf = vec![0; control_size];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
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
                trace!("recv was interrupted, retrying");
                continue;
            }

            return Err(e);
        }
        break n;
    };

    let mut recv_ts = None;

    if log::log_enabled!(log::Level::Trace) {
        if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
            warn!(
                "truncated packet with more than {} bytes from {:?}",
                buf.len(),
                socket.local_addr()
            );
        }

        if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
            warn!(
                "truncated control messages for received packet on socket {:?}",
                socket.local_addr()
            );
        }
    }

    // Loops through the control messages, but we should only get a single message
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&mhdr).as_ref() };
    while let Some(msg) = cmsg {
        if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS_NEW) = (msg.cmsg_level, msg.cmsg_type) {
            // Safety: SCM_TIMESTAMPNS always has a timespec in the data, so this operation should be safe
            let ts: libc::timespec =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(msg) as *const _) };
            recv_ts = Some(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                (ts.tv_sec as u32).wrapping_add(EPOCH_OFFSET), // truncates the higher bits of the i64
                ts.tv_nsec as u32,                             // tv_nsec is always within [0, 1e10)
            ));
            break;
        }

        // grab the next control message
        cmsg = unsafe { libc::CMSG_NXTHDR(&mhdr, msg).as_ref() };
    }

    Ok((n as usize, recv_ts))
}
