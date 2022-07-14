use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    mem::MaybeUninit,
    os::unix::prelude::AsRawFd,
};

use ntp_proto::NtpTimestamp;
use tokio::{io::unix::AsyncFd, net::ToSocketAddrs};
use tracing::{debug, instrument, trace, warn};

// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
// This leads to an offset equivalent to 70 years in seconds
// there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

pub struct UdpSocket {
    io_main: AsyncFd<std::net::UdpSocket>,
    io_timestamp: AsyncFd<std::net::UdpSocket>,
}

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn new<A, B>(listen_addr: A, peer_addr: B) -> io::Result<UdpSocket>
    where
        A: ToSocketAddrs + std::fmt::Debug,
        B: ToSocketAddrs + std::fmt::Debug,
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
        init_socket(&socket)?;

        let socket_timestamp = tokio::net::UdpSocket::bind(&listen_addr).await?;
        socket_timestamp.connect(&listen_addr).await?;
        let socket_timestamp = socket_timestamp.into_std()?;

        Ok(UdpSocket {
            io_main: AsyncFd::new(socket)?,
            io_timestamp: AsyncFd::new(socket_timestamp)?,
        })
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn send(&self, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        trace!(size = buf.len(), "sending bytes");
        loop {
            let mut guard = self.io_main.writable().await?;
            let result = match guard.try_io(|inner| inner.get_ref().send(buf)) {
                // let result = match guard.try_io(|inner| dbg!(send(inner.get_ref(), buf))) {
                Ok(result) => result,
                Err(_would_block) => {
                    trace!("blocked after becoming writable, retrying");
                    continue;
                }
            };

            match &result {
                // Ok((size, ts)) => trace!(size, ts = debug(ts), "received message"),
                Ok(_) => {}
                Err(e) => debug!(error = debug(e), "error receiving data"),
            }

            let x = result?;

            return Ok((x, None));

            // return result;
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
            let mut guard = self.io_main.readable().await?;
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

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn recv_send_timestamp(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<NtpTimestamp>)> {
        loop {
            trace!("waiting for socket to become readable");
            let mut guard = self.io_main.readable().await?;
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
        self.io_main.get_ref()
    }
}

fn init_socket(socket: &std::net::UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    // allow another listener on this socket
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::null_mut(),
            0,
        )
    };

    let software_send: libc::c_int = libc::SOF_TIMESTAMPING_TX_SOFTWARE as _;
    let software_receive: libc::c_int = libc::SOF_TIMESTAMPING_RX_SOFTWARE as _;
    let software_report: libc::c_int = libc::SOF_TIMESTAMPING_SOFTWARE as _;
    // let cmsg: libc::c_int = 1 << 10;
    let generate_id: libc::c_int = 1 << 7; // based on https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/net_tstamp.h#L25

    let bits = software_receive | software_send | software_report | generate_id;

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &bits as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    Ok(())
}

fn recv(socket: &std::net::UdpSocket, buf: &mut [u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    // could be on the stack if const extern fn is stable
    let control_size =
        unsafe { libc::CMSG_SPACE((3 * std::mem::size_of::<libc::timespec>()) as _) } as usize;

    let mut socket_address_storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();

    let mut control_buf = vec![0; control_size];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: (socket_address_storage.as_mut_ptr()).cast(),
        msg_namelen: std::mem::size_of_val(&socket_address_storage) as u32,
    };

    let mut is_self_message = false;

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

        //        let x: [u8; std::mem::size_of::<libc::sockaddr_storage>()] =
        //            unsafe { std::mem::transmute(socket_address_storage) };

        let socket_address_storage = unsafe { socket_address_storage.assume_init() };
        is_self_message = match (socket_address_storage.ss_family) as libc::c_int {
            libc::AF_INET | libc::AF_INET6 => false,
            libc::AF_UNSPEC => true,

            n => {
                warn!("weird ss_family {}", n);
                false
            }
        };

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
            // Safety: SCM_TIMESTAMP always has a timespec in the data, so this operation should be safe
            let ts: libc::timespec =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(msg) as *const _) };

            recv_ts = Some(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                (ts.tv_sec as u32).wrapping_add(EPOCH_OFFSET), // truncates the higher bits of the i64
                ts.tv_nsec as u32,                             // tv_nsec is always within [0, 1e10)
            ));
            dbg!(&recv_ts);
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
