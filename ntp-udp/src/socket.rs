#![forbid(unsafe_code)]

use std::{io, net::SocketAddr};

use ntp_proto::NtpTimestamp;
use tokio::io::{unix::AsyncFd, Interest};
use tracing::instrument;

use crate::{
    interface::InterfaceName,
    raw_socket::{
        control_message_space, receive_message, set_timestamping_options, ControlMessage,
        MessageQueue, TimestampMethod,
    },
    EnableTimestamps,
};

pub struct UdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    send_counter: u32,
    timestamping: EnableTimestamps,
}

#[cfg(target_os = "linux")]
const DEFAULT_TIMESTAMP_METHOD: TimestampMethod = TimestampMethod::SoTimestamping;

#[cfg(all(unix, not(target_os = "linux")))]
const DEFAULT_TIMESTAMP_METHOD: TimestampMethod = TimestampMethod::SoTimestamp;

impl UdpSocket {
    #[instrument(level = "debug", skip(peer_addr))]
    pub async fn client(listen_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<UdpSocket> {
        Self::client_with_timestamping(
            listen_addr,
            peer_addr,
            InterfaceName::DEFAULT,
            EnableTimestamps::default(),
        )
        .await
    }

    pub async fn client_with_timestamping(
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        interface: Option<InterfaceName>,
        timestamping: EnableTimestamps,
    ) -> io::Result<UdpSocket> {
        Self::client_with_timestamping_internal(
            listen_addr,
            peer_addr,
            interface,
            DEFAULT_TIMESTAMP_METHOD,
            timestamping,
        )
        .await
    }

    async fn client_with_timestamping_internal(
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        interface: Option<InterfaceName>,
        method: TimestampMethod,
        timestamping: EnableTimestamps,
    ) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        tracing::debug!(
            local_addr = ?socket.local_addr().unwrap(),
            "client socket bound"
        );

        // bind the socket to a specific interface. This is relevant for hardware timestamping,
        // because the interface determines which clock is used to produce the timestamps.
        if let Some(_interface) = interface {
            #[cfg(target_os = "linux")]
            socket.bind_device(Some(&_interface)).unwrap();
        }

        socket.connect(peer_addr).await?;
        tracing::debug!(
            local_addr = ?socket.local_addr().unwrap(),
            peer_addr = ?socket.peer_addr().unwrap(),
            "client socket connected"
        );

        let socket = socket.into_std()?;

        set_timestamping_options(&socket, method, timestamping)?;

        Ok(UdpSocket {
            io: AsyncFd::new(socket)?,
            send_counter: 0,
            timestamping,
        })
    }

    #[instrument(level = "debug")]
    pub async fn server(
        listen_addr: SocketAddr,
        interface: Option<InterfaceName>,
    ) -> io::Result<UdpSocket> {
        let socket = tokio::net::UdpSocket::bind(listen_addr).await?;
        tracing::debug!(
            local_addr = ?socket.local_addr().unwrap(),
            "server socket bound"
        );

        // bind the socket to a specific interface. This is relevant for hardware timestamping,
        // because the interface determines which clock is used to produce the timestamps.
        if let Some(_interface) = interface {
            #[cfg(target_os = "linux")]
            socket.bind_device(Some(&_interface)).unwrap();
        }

        let socket = socket.into_std()?;

        // our supported kernel versions always have receive timestamping. Send timestamping for a
        // server connection is not relevant, so we don't even bother with checking if it is supported
        let timestamping = EnableTimestamps {
            rx_software: true,
            tx_software: false,
            rx_hardware: false,
            tx_hardware: false,
        };

        set_timestamping_options(&socket, DEFAULT_TIMESTAMP_METHOD, timestamping)?;

        Ok(UdpSocket {
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
        tracing::trace!(size = buf.len(), "sending bytes");

        let result = self
            .io
            .async_io(Interest::WRITABLE, |inner| inner.send(buf))
            .await;

        let send_size = match result {
            Ok(size) => {
                tracing::trace!(sent = size, "sent bytes");
                size
            }
            Err(e) => {
                tracing::debug!(error = debug(&e), "error sending data");
                return Err(e);
            }
        };

        debug_assert_eq!(buf.len(), send_size);

        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        if self.timestamping.tx_software {
            #[cfg(target_os = "linux")]
            {
                // the send timestamp may never come set a very short timeout to prevent hanging forever.
                // We automatically fall back to a less accurate timestamp when this function returns None
                let timeout = std::time::Duration::from_millis(10);
                match tokio::time::timeout(timeout, self.fetch_send_timestamp(expected_counter))
                    .await
                {
                    Err(_) => {
                        tracing::warn!("Packet without timestamp");
                        Ok((send_size, None))
                    }
                    Ok(send_timestamp) => Ok((send_size, Some(send_timestamp?))),
                }
            }

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                let _ = expected_counter;
                Ok((send_size, None))
            }
        } else {
            tracing::trace!("send timestamping not supported");
            Ok((send_size, None))
        }
    }

    #[cfg(target_os = "linux")]
    async fn fetch_send_timestamp(&self, expected_counter: u32) -> io::Result<NtpTimestamp> {
        let msg = "waiting for timestamp socket to become readable to fetch a send timestamp";
        tracing::trace!(msg);

        let try_read = |udp_socket: &std::net::UdpSocket| {
            fetch_send_timestamp_help(udp_socket, expected_counter)
        };

        loop {
            // the timestamp being available triggers the error interest
            match self.io.async_io(Interest::ERROR, try_read).await? {
                Some(timestamp) => return Ok(timestamp),
                None => continue,
            };
        }
    }

    #[instrument(level = "trace", skip(self, buf), fields(
        local_addr = debug(self.as_ref().local_addr().unwrap()),
        buf_size = buf.len(),
    ))]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        tracing::trace!(size = buf.len(), ?addr, "sending bytes");

        let result = self
            .io
            .async_io(Interest::WRITABLE, |inner| inner.send_to(buf, addr))
            .await;

        match &result {
            Ok(size) => tracing::trace!(sent = size, "sent bytes"),
            Err(e) => tracing::debug!(error = debug(e), "error sending data"),
        }

        result
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
        tracing::trace!("waiting for socket to become readable");

        let result = self
            .io
            .async_io(Interest::READABLE, |inner| recv(inner, buf))
            .await;

        match &result {
            Ok((size, addr, ts)) => {
                tracing::trace!(size, ts = ?ts, addr = ?addr, "received message");
            }
            Err(e) => tracing::debug!(error = ?e, "error receiving data"),
        }

        result
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
    let (bytes_read, control_messages, sock_addr) =
        receive_message(socket, buf, &mut control_buf, MessageQueue::Normal)?;
    let sock_addr =
        sock_addr.unwrap_or_else(|| unreachable!("We never constructed a non-ip socket"));

    // Loops through the control messages, but we should only get a single message in practice
    for msg in control_messages {
        match msg {
            ControlMessage::Timestamping(libc_timestamp) => {
                let ntp_timestamp = libc_timestamp.into_ntp_timestamp();
                return Ok((bytes_read as usize, sock_addr, Some(ntp_timestamp)));
            }

            #[cfg(target_os = "linux")]
            ControlMessage::ReceiveError(_error) => {
                tracing::warn!("unexpected error message on the MSG_ERRQUEUE");
            }

            ControlMessage::Other(msg) => {
                tracing::warn!(
                    "weird control message {:?} {:?}",
                    msg.cmsg_level,
                    msg.cmsg_type
                );
            }
        }
    }

    Ok((bytes_read as usize, sock_addr, None))
}

#[cfg(target_os = "linux")]
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

    let (_, control_messages, _) =
        receive_message(socket, &mut [], &mut control_buf, MessageQueue::Error)?;

    let mut send_ts = None;
    for msg in control_messages {
        match msg {
            ControlMessage::Timestamping(timestamp) => {
                send_ts = Some(timestamp);
            }

            ControlMessage::ReceiveError(error) => {
                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    tracing::warn!(
                        expected_counter,
                        error.ee_data,
                        "error message on the MSG_ERRQUEUE"
                    );
                }

                // Check that this message belongs to the send we are interested in
                if error.ee_data != expected_counter {
                    tracing::debug!(
                        error.ee_data,
                        expected_counter,
                        "Timestamp for unrelated packet"
                    );
                    return Ok(None);
                }
            }

            ControlMessage::Other(msg) => {
                tracing::warn!(
                    msg.cmsg_level,
                    msg.cmsg_type,
                    "unexpected message on the MSG_ERRQUEUE",
                );
            }
        }
    }

    Ok(send_ts.map(|ts| ts.into_ntp_timestamp()))
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
        let a = UdpSocket::server("127.0.0.1:10002".parse().unwrap(), InterfaceName::DEFAULT)
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
        let a = UdpSocket::server("[::1]:10002".parse().unwrap(), InterfaceName::DEFAULT)
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

    async fn timestamping_reasonable(method: TimestampMethod, p1: u16, p2: u16) {
        let mut a = UdpSocket::client(
            SocketAddr::from((Ipv4Addr::LOCALHOST, p1)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, p2)),
        )
        .await
        .unwrap();
        let b = UdpSocket::client_with_timestamping_internal(
            SocketAddr::from((Ipv4Addr::LOCALHOST, p2)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, p1)),
            InterfaceName::DEFAULT,
            method,
            EnableTimestamps {
                rx_software: true,
                tx_software: true,
                rx_hardware: false,
                tx_hardware: false,
            },
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

        // this can be flaky on freebsd
        assert!(
            delta.to_seconds() > 0.15 && delta.to_seconds() < 0.25,
            "delta was {}s",
            delta.to_seconds()
        );
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn timestamping_reasonable_so_timestamping() {
        timestamping_reasonable(TimestampMethod::SoTimestamping, 8000, 8001).await;
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn timestamping_reasonable_so_timestampns() {
        timestamping_reasonable(TimestampMethod::SoTimestampns, 8002, 8003).await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn timestamping_reasonable_so_timestamp() {
        timestamping_reasonable(TimestampMethod::SoTimestamp, 8004, 8005).await;
    }

    #[tokio::test]
    #[cfg_attr(
        any(target_os = "macos", target_os = "freebsd"),
        ignore = "send timestamps are not supported"
    )]
    async fn test_send_timestamp() {
        let mut a = UdpSocket::client_with_timestamping(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8012)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8013)),
            InterfaceName::DEFAULT,
            EnableTimestamps {
                rx_software: true,
                tx_software: true,
                rx_hardware: false,
                tx_hardware: false,
            },
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
