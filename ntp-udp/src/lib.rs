use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    os::unix::prelude::{AsRawFd, FromRawFd, RawFd},
};

use ntp_proto::NtpTimestamp;
use tokio::io::unix::AsyncFd;
use tracing::{debug, instrument, trace, warn};

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
}

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn new<A, B>(listen_addr: A, peer_addr: B) -> io::Result<UdpSocket>
    where
        A: tokio::net::ToSocketAddrs + std::net::ToSocketAddrs + std::fmt::Debug,
        B: tokio::net::ToSocketAddrs + std::net::ToSocketAddrs + std::fmt::Debug,
    {
        let unbound_socket = UnboundSocket::new(&listen_addr)?;
        unbound_socket.set_reuse_port()?;
        unbound_socket.set_timestamping()?;

        let socket = unbound_socket.bind_tokio()?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "socket bound"
        );
        socket.connect(peer_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            peer_addr = debug(socket.peer_addr().unwrap()),
            "socket connected"
        );
        let socket = socket.into_std()?;
        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
        })
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        trace!(size = buf.len(), "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => {
                    match &result {
                        Ok(size) => trace!(sent = size, "sent bytes"),
                        Err(e) => debug!(error = debug(e), "error sending data"),
                    }
                    return result;
                }
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        loop {
            trace!("waiting for socket to become readable");
            let mut guard = self.io.readable().await?;
            let result = match guard.try_io(|inner| recv(inner.get_ref(), buf)) {
                Err(_would_block) => {
                    trace!("blocked after becoming readable, retrying");
                    continue;
                }
                Ok(result) => result,
            };
            match &result {
                Ok((size, ts)) => trace!(size, ts = debug(ts), "received message"),
                Err(e) => debug!(error = debug(e), "error receiving data"),
            }
            return result;
        }
    }
}

impl AsRef<std::net::UdpSocket> for UdpSocket {
    fn as_ref(&self) -> &std::net::UdpSocket {
        self.io.get_ref()
    }
}

fn recv(socket: &std::net::UdpSocket, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    // could be on the stack if const extern fn is stable
    let control_size =
        unsafe { libc::CMSG_SPACE((3 * std::mem::size_of::<libc::timespec>()) as _) } as usize;
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

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!(
            max_len = buf.len(),
            "truncated packet because it was larger than expected",
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    // Loops through the control messages, but we should only get a single message
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&mhdr).as_ref() };
    while let Some(msg) = cmsg {
        if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) = (msg.cmsg_level, msg.cmsg_type) {
            // Safety: SCM_TIMESTAMPING always has a timespec in the data, so this operation should be safe
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamping_reasonable() {
        tokio_test::block_on(async {
            let a = UdpSocket::new("127.0.0.1:8000", "127.0.0.1:8001")
                .await
                .unwrap();
            let b = UdpSocket::new("127.0.0.1:8001", "127.0.0.1:8000")
                .await
                .unwrap();

            tokio::spawn(async move {
                a.send(&[1; 48]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                a.send(&[2; 48]).await.unwrap();
            });

            let mut buf = [0; 48];
            let (s1, t1) = b.recv(&mut buf).await.unwrap();
            let (s2, t2) = b.recv(&mut buf).await.unwrap();
            assert_eq!(s1, 48);
            assert_eq!(s2, 48);

            let t1 = t1.unwrap();
            let t2 = t2.unwrap();
            let delta = t2 - t1;

            assert!(delta.to_seconds() > 0.15 && delta.to_seconds() < 0.25);
        });
    }
}

pub fn cvt(t: libc::c_int) -> crate::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

struct UnboundSocket {
    fd: RawFd,
    addr: std::net::SocketAddr,
}

impl UnboundSocket {
    fn new<A: std::net::ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        use std::net::SocketAddr;

        let mut last_error = None;

        for addr in addr.to_socket_addrs()? {
            let fam = match addr {
                SocketAddr::V4(..) => libc::AF_INET,
                SocketAddr::V6(..) => libc::AF_INET6,
            };

            let ty = libc::SOCK_DGRAM;

            // NOTE: only works on linux
            // see https://github.com/rust-lang/rust/blob/master/library/std/src/sys/unix/net.rs#L70
            unsafe {
                // On platforms that support it we pass the SOCK_CLOEXEC
                // flag to atomically create the socket and set it as
                // CLOEXEC. On Linux this was added in 2.6.27.
                match libc::socket(fam, ty | libc::SOCK_CLOEXEC, 0) {
                    -1 => {
                        last_error = Some(std::io::Error::last_os_error());
                        // try the other addresses
                        continue;
                    }
                    fd => return Ok(UnboundSocket { fd, addr }),
                };
            }
        }

        let default_error = std::io::Error::new(
            ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        );

        Err(last_error.unwrap_or(default_error))
    }

    fn addr_into_inner(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        use std::net::SocketAddr;

        match self.addr {
            SocketAddr::V4(ref a) => (
                a as *const _ as *const _,
                std::mem::size_of_val(a) as libc::socklen_t,
            ),
            SocketAddr::V6(ref a) => (
                a as *const _ as *const _,
                std::mem::size_of_val(a) as libc::socklen_t,
            ),
        }
    }

    fn set_reuse_port(&self) -> std::io::Result<()> {
        let optval: i32 = 1;

        // allow another listener on this socket
        unsafe {
            cvt(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const i32 as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?
        };

        Ok(())
    }

    fn set_timestamping(&self) -> io::Result<()> {
        let fd = self.fd;

        let software_send: libc::c_int = libc::SOF_TIMESTAMPING_TX_SOFTWARE as _;
        let software_receive: libc::c_int = libc::SOF_TIMESTAMPING_RX_SOFTWARE as _;
        let software_report: libc::c_int = libc::SOF_TIMESTAMPING_SOFTWARE as _;

        let bits = software_receive | software_send | software_report;

        unsafe {
            cvt(libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &bits as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))?
        };

        Ok(())
    }

    fn bind_nonblocking(self) -> std::io::Result<std::net::UdpSocket> {
        unsafe {
            let (addrp, len) = self.addr_into_inner();

            cvt(libc::bind(self.fd, addrp, len as _))?;

            let udp_socket = std::net::UdpSocket::from_raw_fd(self.fd);
            udp_socket.set_nonblocking(true)?;
            Ok(udp_socket)
        }
    }

    fn bind_tokio(self) -> std::io::Result<tokio::net::UdpSocket> {
        tokio::net::UdpSocket::from_std(self.bind_nonblocking()?)
    }
}
