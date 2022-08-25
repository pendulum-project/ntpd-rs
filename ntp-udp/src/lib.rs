use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    mem::{size_of, MaybeUninit},
    net::{Ipv4Addr, SocketAddr},
    os::unix::prelude::AsRawFd,
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
    pub async fn client(listen_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "client socket bound"
        );

        socket.connect(peer_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            peer_addr = debug(socket.peer_addr().unwrap()),
            "client socket connected"
        );

        let socket = socket.into_std()?;
        set_timestamping_options(&socket)?;
        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
        })
    }

    #[instrument(level = "debug")]
    pub async fn server(listen_addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        debug!(
            local_addr = debug(socket.local_addr().unwrap()),
            "server socket bound"
        );

        let socket = socket.into_std()?;
        set_timestamping_options(&socket)?;
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
        buf_size = buf.len(),
    ))]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        trace!(size = buf.len(), ?addr, "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
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
        peer_addr = debug(self.as_ref().peer_addr().ok()),
        buf_size = buf.len(),
    ))]
    pub async fn recv(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
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
                Ok((size, addr, ts)) => {
                    trace!(size, ts = debug(ts), addr = debug(addr), "received message")
                }
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

fn set_timestamping_options(udp_socket: &std::net::UdpSocket) -> io::Result<()> {
    let fd = udp_socket.as_raw_fd();

    // our options:
    //  - we want software timestamps to be reported,
    //  - we want receive software timestamps
    let options = libc::SOF_TIMESTAMPING_SOFTWARE | libc::SOF_TIMESTAMPING_RX_SOFTWARE;

    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &options as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ))?
    };

    Ok(())
}

/// Turn a C failure (-1 is returned) into a rust Result
fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}

/// # Safety
///
/// The given pointer must point to a libc::timespec
unsafe fn read_ntp_timestamp(ptr: *const u8) -> NtpTimestamp {
    let ts: libc::timespec = std::ptr::read_unaligned(ptr as *const _);

    // truncates the higher bits of the i64
    let seconds = (ts.tv_sec as u32).wrapping_add(EPOCH_OFFSET);

    // tv_nsec is always within [0, 1e10)
    let nanos = ts.tv_nsec as u32;

    NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
}

/// Receive a message on a socket (retry if interrupted)
fn receive_message(
    socket: &std::net::UdpSocket,
    message_header: &mut libc::msghdr,
    flags: libc::c_int,
) -> io::Result<libc::c_int> {
    loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), message_header, flags) } as _) {
            Err(e) if ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => return other,
        }
    }
}

fn control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = &libc::cmsghdr> {
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
const fn control_message_space<T>() -> usize {
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

fn recv(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];
    let mut addr = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: addr.as_mut_ptr().cast::<libc::c_void>(),
        msg_namelen: size_of::<libc::sockaddr_storage>() as u32,
    };

    // loops for when we receive an interrupt during the recv
    let flags = 0;
    let bytes_read = receive_message(socket, &mut mhdr, flags)? as usize;

    let addr = unsafe { addr.assume_init() };
    let sock_addr = match addr.ss_family as i32 {
        libc::AF_INET => {
            // kernel assures us this conversion is safe
            let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in;
            let sin = unsafe { &*sin };
            let [a, b, c, d] = sin.sin_addr.s_addr.to_ne_bytes();

            // no direct (u32, u16) conversion is available, so we convert the address first
            let addr = Ipv4Addr::new(a, b, c, d);
            SocketAddr::from((addr, u16::from_be_bytes(sin.sin_port.to_ne_bytes())))
        }
        libc::AF_INET6 => {
            // kernel assures us this conversion is safe
            let sin = &addr as *const _ as *const libc::c_void as *const libc::sockaddr_in6;
            let sin = unsafe { &*sin };
            SocketAddr::from((
                sin.sin6_addr.s6_addr,
                u16::from_be_bytes(sin.sin6_port.to_ne_bytes()),
            ))
        }
        _ => {
            unreachable!("We never constructed a non-ip socket");
        }
    };

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!(
            max_len = buf.len(),
            "truncated packet because it was larger than expected",
        );
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    // Loops through the control messages, but we should only get a single message in practice
    for msg in control_messages(&mhdr) {
        if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) = (msg.cmsg_level, msg.cmsg_type) {
            // Safety: SO_TIMESTAMPING always has a timespec in the data
            let timestamp = unsafe { read_ntp_timestamp(libc::CMSG_DATA(msg)) };

            return Ok((bytes_read, sock_addr, Some(timestamp)));
        }
    }

    Ok((bytes_read, sock_addr, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamping_reasonable() {
        tokio_test::block_on(async {
            let a = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
            )
            .await
            .unwrap();
            let b = UdpSocket::client(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                a.send(&[1; 48]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                a.send(&[2; 48]).await.unwrap();
            });

            let mut buf = [0; 48];
            let (s1, _, t1) = b.recv(&mut buf).await.unwrap();
            let (s2, _, t2) = b.recv(&mut buf).await.unwrap();
            assert_eq!(s1, 48);
            assert_eq!(s2, 48);

            let t1 = t1.unwrap();
            let t2 = t2.unwrap();
            let delta = t2 - t1;

            assert!(delta.to_seconds() > 0.15 && delta.to_seconds() < 0.25);
        });
    }
}
