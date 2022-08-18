use std::{
    io,
    io::{ErrorKind, IoSliceMut},
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
    pub async fn new<A, B>(listen_addr: A, peer_addr: B) -> io::Result<UdpSocket>
    where
        A: tokio::net::ToSocketAddrs + std::fmt::Debug,
        B: tokio::net::ToSocketAddrs + std::fmt::Debug,
    {
        let socket = tokio::net::UdpSocket::bind(&listen_addr).await?;
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
    pub async fn send(&self, buf: &[u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        let send_size = self.send_help(buf).await?;

        // the send timestamp may never come (when the driver does not support send timestamping)
        // set a very short timeout to prevent hanging forever. We automatically fall back to a
        // less accurate timestamp when this function returns None
        let timeout = std::time::Duration::from_millis(10);
        match tokio::time::timeout(timeout, self.fetch_send_timestamp()).await {
            Err(_) => Ok((send_size, None)),
            Ok(send_timestamp) => Ok((send_size, send_timestamp?)),
        }
    }

    async fn send_help(&self, buf: &[u8]) -> io::Result<usize> {
        trace!(size = buf.len(), "sending bytes");
        loop {
            let mut guard = self.io.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => match result {
                    Err(e) => {
                        debug!(error = debug(&e), "error sending data");
                        return Err(e);
                    }
                    Ok(size) => {
                        trace!(sent = size, "sent bytes");
                        return Ok(size);
                    }
                },
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            }
        }
    }

    async fn fetch_send_timestamp(&self) -> io::Result<Option<NtpTimestamp>> {
        trace!("waiting for socket to become readable");
        loop {
            let mut guard = self.io.readable().await?;
            match guard.try_io(|inner| fetch_send_timestamp_help(inner.get_ref())) {
                Ok(send_timestamp) => {
                    return send_timestamp;
                }
                Err(_would_block) => {
                    trace!("blocked after becoming readable, retrying");
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

/// Makes the kernel return the timestamp as a cmsg alongside an empty packet,
/// as opposed to alongside the original packet
const SOF_TIMESTAMPING_OPT_TSONLY: u32 = 1 << 11;

fn set_timestamping_options(udp_socket: &std::net::UdpSocket) -> io::Result<()> {
    let fd = udp_socket.as_raw_fd();

    // our options:
    //  - we want software timestamps to be reported,
    //  - we want both send and receive software timestamps
    //  - return just the timestamp, don't send the full message along
    let options = libc::SOF_TIMESTAMPING_SOFTWARE
        | libc::SOF_TIMESTAMPING_RX_SOFTWARE
        | libc::SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_OPT_TSONLY;

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

fn recv(socket: &std::net::UdpSocket, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    // could be on the stack if const extern fn is stable
    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];
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
    let flags = 0;
    let bytes_read = receive_message(socket, &mut mhdr, flags)? as usize;

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

            return Ok((bytes_read, Some(timestamp)));
        }
    }

    Ok((bytes_read, None))
}

fn fetch_send_timestamp_help(socket: &std::net::UdpSocket) -> io::Result<Option<NtpTimestamp>> {
    // we get back two control messages: one with the timestamp (just like a receive timestamp),
    // and one error message with no error reason. The payload for this second message is kind of
    // undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket address. The linux
    // kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
    const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = [0; CONTROL_SIZE];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_flags: 0,
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
    };

    receive_message(socket, &mut mhdr, libc::MSG_ERRQUEUE)?;

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!("truncated packet because it was larger than expected",);
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    let mut send_ts = None;
    for msg in control_messages(&mhdr) {
        match (msg.cmsg_level, msg.cmsg_type) {
            (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) => {
                // Safety: SCM_TIMESTAMP always has a timespec in the data, so this operation should be safe
                send_ts = Some(unsafe { read_ntp_timestamp(libc::CMSG_DATA(msg)) });

                break;
            }
            (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                // this is part of how timestamps are reported.
                let error = unsafe {
                    let ptr: *const u8 = libc::CMSG_DATA(msg);
                    std::ptr::read_unaligned::<libc::sock_extended_err>(ptr as *const _)
                };

                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    warn!("error message on the MSG_ERRQUEUE");
                }
            }
            _ => {
                warn!(
                    msg.cmsg_level,
                    msg.cmsg_type, "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok(send_ts)
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
