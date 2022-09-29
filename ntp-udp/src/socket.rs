#![forbid(unsafe_code)]

use std::{io, net::SocketAddr, os::unix::prelude::RawFd};

use ntp_proto::NtpTimestamp;
use tokio::io::unix::AsyncFd;
use tracing::{debug, instrument, trace, warn};

use crate::raw_socket::{
    control_message_space, control_messages, exceptional_condition_fd, receive_message,
    set_timestamping_options, ControlMessage, MessageQueue, TimestampingConfig,
};

enum Timestamping {
    Configure(TimestampingConfig),
    #[allow(dead_code)]
    AllSupported,
}

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    exceptional_condition: AsyncFd<RawFd>,
    send_counter: u32,
    timestamping: TimestampingConfig,
}

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn client(listen_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<UdpSocket> {
        // disable tx timestamping for now (outside of tests)
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        Self::client_with_timestamping(
            listen_addr,
            peer_addr,
            Timestamping::Configure(timestamping),
        )
        .await
    }

    async fn client_with_timestamping(
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        timestamping: Timestamping,
    ) -> io::Result<UdpSocket> {
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

        let timestamping = match timestamping {
            Timestamping::Configure(config) => config,
            Timestamping::AllSupported => TimestampingConfig::all_supported(&socket)?,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            exceptional_condition: exceptional_condition_fd(&socket)?,
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
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

        // our supported kernel versions always have receive timestamping. Send timestamping for a
        // server connection is not relevant, so we don't even bother with checking if it is supported
        let timestamping = TimestampingConfig {
            rx_software: true,
            tx_software: false,
        };

        set_timestamping_options(&socket, timestamping)?;

        Ok(UdpSocket {
            exceptional_condition: exceptional_condition_fd(&socket)?,
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        peer_addr = debug(self.as_ref().peer_addr()),
        buf_size = buf.len(),
    ))]
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<(usize, Option<NtpTimestamp>)> {
        let send_size = self.send_help(buf).await?;
        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        if self.timestamping.tx_software {
            // the send timestamp may never come set a very short timeout to prevent hanging forever.
            // We automatically fall back to a less accurate timestamp when this function returns None
            let timeout = std::time::Duration::from_millis(10);

            match tokio::time::timeout(timeout, self.fetch_send_timestamp(expected_counter)).await {
                Err(_) => {
                    warn!("Packet without timestamp");
                    Ok((send_size, None))
                }
                Ok(send_timestamp) => Ok((send_size, Some(send_timestamp?))),
            }
        } else {
            trace!("send timestamping not supported");
            Ok((send_size, None))
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

    async fn fetch_send_timestamp(&self, expected_counter: u32) -> io::Result<NtpTimestamp> {
        trace!("waiting for timestamp socket to become readable to fetch a send timestamp");
        loop {
            // Send timestamps are sent to the udp socket's error queue. Sadly, tokio does not
            // currently support awaiting whether there is something in the error queue
            // see https://github.com/tokio-rs/tokio/issues/4885.
            //
            // Therefore, we manually configure an extra file descriptor to listen for POLLPRI on
            // the main udp socket. This `exceptional_condition` file descriptor becomes readable
            // when there is something in the error queue.
            let mut guard = self.exceptional_condition.readable().await?;
            match guard.try_io(|_| fetch_send_timestamp_help(self.io.get_ref(), expected_counter)) {
                Ok(Ok(Some(send_timestamp))) => {
                    return Ok(send_timestamp);
                }
                Ok(Ok(None)) => {
                    continue;
                }
                Ok(Err(e)) => {
                    warn!(error = debug(&e), "Error fetching timestamp");
                    return Err(e);
                }
                Err(_would_block) => {
                    trace!("timestamp blocked after becoming readable, retrying");
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

fn recv(
    socket: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<NtpTimestamp>)> {
    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];

    // loops for when we receive an interrupt during the recv
    let (bytes_read, mhdr, sock_addr) =
        receive_message(socket, buf, &mut control_buf, MessageQueue::Normal)?;
    let sock_addr =
        sock_addr.unwrap_or_else(|| unreachable!("We never constructed a non-ip socket"));

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
        match msg {
            ControlMessage::Timestamping(timespec) => {
                let timestamp = read_ntp_timestamp(timespec);

                return Ok((bytes_read as usize, sock_addr, Some(timestamp)));
            }

            ControlMessage::ReceiveError(_error) => {
                warn!("unexpected error message on the MSG_ERRQUEUE");
            }

            ControlMessage::Other(msg) => {
                warn!(
                    msg.cmsg_level,
                    msg.cmsg_type, "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok((bytes_read as usize, sock_addr, None))
}

fn fetch_send_timestamp_help(
    socket: &std::net::UdpSocket,
    expected_counter: u32,
) -> io::Result<Option<NtpTimestamp>> {
    // we get back two control messages: one with the timestamp (just like a receive timestamp),
    // and one error message with no error reason. The payload for this second message is kind of
    // undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket address. The linux
    // kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
    //
    // sockaddr_storage is bigger than we need, but sockaddr is too small for ipv6
    const CONTROL_SIZE: usize = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = [0; CONTROL_SIZE];

    let (_, mhdr, _) = receive_message(socket, &mut [], &mut control_buf, MessageQueue::Error)?;

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        warn!("truncated packet because it was larger than expected",);
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        warn!("truncated control messages");
    }

    let mut send_ts = None;
    for msg in control_messages(&mhdr) {
        match msg {
            ControlMessage::Timestamping(timespec) => {
                send_ts = Some(read_ntp_timestamp(timespec));
            }

            ControlMessage::ReceiveError(error) => {
                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    warn!(
                        expected_counter,
                        error.ee_data, "error message on the MSG_ERRQUEUE"
                    );
                }

                // Check that this message belongs to the send we are interested in
                if error.ee_data != expected_counter {
                    warn!(
                        error.ee_data,
                        expected_counter, "Timestamp for unrelated packet"
                    );
                    return Ok(None);
                }
            }

            ControlMessage::Other(msg) => {
                warn!(
                    msg.cmsg_level,
                    msg.cmsg_type, "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok(send_ts)
}

fn read_ntp_timestamp(timespec: libc::timespec) -> NtpTimestamp {
    // Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
    // This leads to an offset equivalent to 70 years in seconds
    // there are 17 leap years between the two dates so the offset is
    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

    // truncates the higher bits of the i64
    let seconds = (timespec.tv_sec as u32).wrapping_add(EPOCH_OFFSET);

    // tv_nsec is always within [0, 1e10)
    let nanos = timespec.tv_nsec as u32;

    NtpTimestamp::from_seconds_nanos_since_ntp_era(seconds, nanos)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[tokio::test]
    async fn test_client_basic_ipv4() {
        let mut a = UdpSocket::client(
            "127.0.0.1:10000".parse().unwrap(),
            "127.0.0.1:10001".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut b = UdpSocket::client(
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:10000".parse().unwrap(),
        )
        .await
        .unwrap();

        a.send(&[1; 48]).await.unwrap();
        let mut buf = [0; 48];
        let (size, addr, _) = b.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "127.0.0.1:10000".parse().unwrap());
        assert_eq!(buf, [1; 48]);

        b.send(&[2; 48]).await.unwrap();
        let (size, addr, _) = a.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "127.0.0.1:10001".parse().unwrap());
        assert_eq!(buf, [2; 48]);
    }

    #[tokio::test]
    async fn test_client_basic_ipv6() {
        let mut a = UdpSocket::client(
            "[::1]:10000".parse().unwrap(),
            "[::1]:10001".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut b = UdpSocket::client(
            "[::1]:10001".parse().unwrap(),
            "[::1]:10000".parse().unwrap(),
        )
        .await
        .unwrap();

        a.send(&[1; 48]).await.unwrap();
        let mut buf = [0; 48];
        let (size, addr, _) = b.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "[::1]:10000".parse().unwrap());
        assert_eq!(buf, [1; 48]);

        b.send(&[2; 48]).await.unwrap();
        let (size, addr, _) = a.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "[::1]:10001".parse().unwrap());
        assert_eq!(buf, [2; 48]);
    }

    #[tokio::test]
    async fn test_server_basic_ipv4() {
        let a = UdpSocket::server("127.0.0.1:10002".parse().unwrap())
            .await
            .unwrap();
        let mut b = UdpSocket::client(
            "127.0.0.1:10003".parse().unwrap(),
            "127.0.0.1:10002".parse().unwrap(),
        )
        .await
        .unwrap();

        b.send(&[1; 48]).await.unwrap();
        let mut buf = [0; 48];
        let (size, addr, _) = a.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "127.0.0.1:10003".parse().unwrap());
        assert_eq!(buf, [1; 48]);

        a.send_to(&[2; 48], addr).await.unwrap();
        let (size, addr, _) = b.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "127.0.0.1:10002".parse().unwrap());
        assert_eq!(buf, [2; 48]);
    }

    #[tokio::test]
    async fn test_server_basic_ipv6() {
        let a = UdpSocket::server("[::1]:10002".parse().unwrap())
            .await
            .unwrap();
        let mut b = UdpSocket::client(
            "[::1]:10003".parse().unwrap(),
            "[::1]:10002".parse().unwrap(),
        )
        .await
        .unwrap();

        b.send(&[1; 48]).await.unwrap();
        let mut buf = [0; 48];
        let (size, addr, _) = a.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "[::1]:10003".parse().unwrap());
        assert_eq!(buf, [1; 48]);

        a.send_to(&[2; 48], addr).await.unwrap();
        let (size, addr, _) = b.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert_eq!(addr, "[::1]:10002".parse().unwrap());
        assert_eq!(buf, [2; 48]);
    }

    #[tokio::test]
    async fn test_timestamping_reasonable() {
        let mut a = UdpSocket::client_with_timestamping(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8001)),
            Timestamping::AllSupported,
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
    }

    #[tokio::test]
    async fn test_send_timestamp() {
        let mut a = UdpSocket::client_with_timestamping(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
            Timestamping::AllSupported,
        )
        .await
        .unwrap();
        let b = UdpSocket::client(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
        )
        .await
        .unwrap();

        let (ssend, tsend) = a.send(&[1; 48]).await.unwrap();
        let mut buf = [0; 48];
        let (srecv, _, trecv) = b.recv(&mut buf).await.unwrap();

        assert_eq!(ssend, 48);
        assert_eq!(srecv, 48);

        let tsend = tsend.unwrap();
        let trecv = trecv.unwrap();
        let delta = trecv - tsend;
        assert!(delta.to_seconds().abs() < 0.2);
    }
}
