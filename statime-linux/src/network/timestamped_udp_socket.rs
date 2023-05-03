#![forbid(unsafe_code)]

use std::{io, net::SocketAddr, os::unix::prelude::RawFd};

use statime::{clock::Clock, time::Instant};
use tokio::io::{unix::AsyncFd, Interest};

use super::{
    control_message::{control_message_space, ControlMessage, MessageQueue},
    linux::TimestampingMode,
    raw_udp_socket::{exceptional_condition_fd, receive_message, set_timestamping_options},
};
use crate::clock::{libc_timespec_into_instant, LinuxClock};

pub struct TimestampedUdpSocket {
    io: AsyncFd<std::net::UdpSocket>,
    exceptional_condition: AsyncFd<RawFd>,
    send_counter: u32,
}

impl TimestampedUdpSocket {
    pub fn from_udp_socket(
        io: std::net::UdpSocket,
        timestamping_mode: TimestampingMode,
    ) -> std::io::Result<Self> {
        set_timestamping_options(&io, timestamping_mode)?;

        Ok(Self {
            exceptional_condition: exceptional_condition_fd(&io)?,
            io: AsyncFd::new(io)?,
            send_counter: 0,
        })
    }

    pub async fn recv(&self, clock: &LinuxClock, buf: &mut [u8]) -> std::io::Result<RecvResult> {
        let receiver = |inner: &std::net::UdpSocket| recv_with_timestamp(inner, clock, buf);
        self.io.async_io(Interest::READABLE, receiver).await
    }

    pub async fn send(
        &mut self,
        data: &[u8],
        address: SocketAddr,
    ) -> std::io::Result<Option<Instant>> {
        self.send_to(data, address).await?;

        let expected_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        self.fetch_send_timestamp(expected_counter).await
    }

    async fn send_to(&self, data: &[u8], address: SocketAddr) -> std::io::Result<usize> {
        let sender = |inner: &std::net::UdpSocket| inner.send_to(data, address);
        self.io.async_io(Interest::WRITABLE, sender).await
    }

    async fn fetch_send_timestamp(
        &self,
        expected_counter: u32,
    ) -> std::io::Result<Option<Instant>> {
        // the send timestamp may never come set a very short timeout to prevent hanging
        // forever. We automatically fall back to a less accurate timestamp when
        // this function returns None
        let timeout = std::time::Duration::from_millis(10);

        let fetch = self.fetch_send_timestamp_help(expected_counter);
        if let Ok(send_timestamp) = tokio::time::timeout(timeout, fetch).await {
            Ok(Some(send_timestamp?))
        } else {
            log::warn!("Packet without timestamp (waiting for timestamp timed out)");
            eprintln!("Packet without timestamp (waiting for timestamp timed out)");
            Ok(None)
        }
    }

    async fn fetch_send_timestamp_help(&self, expected_counter: u32) -> std::io::Result<Instant> {
        log::trace!("waiting for timestamp socket to become readable to fetch a send timestamp");

        // Send timestamps are sent to the udp socket's error queue. Sadly, tokio does
        // not currently support awaiting whether there is something in the
        // error queue see https://github.com/tokio-rs/tokio/issues/4885.
        //
        // Therefore, we manually configure an extra file descriptor to listen for
        // POLLPRI on the main udp socket. This `exceptional_condition` file
        // descriptor becomes readable when there is something in the error
        // queue.

        loop {
            let result = self
                .exceptional_condition
                .async_io(Interest::READABLE, |_| {
                    fetch_send_timestamp_help(self.io.get_ref(), expected_counter)
                })
                .await;

            match result {
                Ok(Some(send_timestamp)) => {
                    return Ok(send_timestamp);
                }
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    log::warn!("Error fetching timestamp: {e:?}");
                    return Err(e);
                }
            }
        }
    }
}

pub struct RecvResult {
    pub bytes_read: usize,
    pub peer_address: SocketAddr,
    pub timestamp: Instant,
}

fn recv_with_timestamp(
    tc_socket: &std::net::UdpSocket,
    clock: &LinuxClock,
    read_buf: &mut [u8],
) -> std::io::Result<RecvResult> {
    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];

    // loops for when we receive an interrupt during the recv
    let (bytes_read, control_messages, peer_address) =
        receive_message(tc_socket, read_buf, &mut control_buf, MessageQueue::Normal)?;

    let mut timestamp = clock.now();

    // Loops through the control messages, but we should only get a single message
    // in practice
    for msg in control_messages {
        match msg {
            ControlMessage::Timestamping(timespec) => {
                timestamp = libc_timespec_into_instant(timespec);
            }

            ControlMessage::ReceiveError(_error) => {
                log::warn!("unexpected error message on the MSG_ERRQUEUE");
            }

            ControlMessage::Other(msg) => {
                log::warn!(
                    "unexpected message on the MSG_ERRQUEUE (level = {}, type = {})",
                    msg.cmsg_level,
                    msg.cmsg_type,
                );
            }
        }
    }

    let msg = "We never constructed a non-ip socket";
    let peer_address = peer_address.unwrap_or_else(|| unreachable!("{}", msg));

    let result = RecvResult {
        bytes_read,
        peer_address,
        timestamp,
    };

    Ok(result)
}

fn fetch_send_timestamp_help(
    socket: &std::net::UdpSocket,
    expected_counter: u32,
) -> io::Result<Option<Instant>> {
    // we get back two control messages: one with the timestamp (just like a receive
    // timestamp), and one error message with no error reason. The payload for
    // this second message is kind of undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket
    // address. The linux kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
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
                    log::warn!(
                        "error message on the MSG_ERRQUEUE: expected message {}, it has error \
                         code {}",
                        expected_counter,
                        error.ee_data,
                    );
                }

                // Check that this message belongs to the send we are interested in
                if error.ee_data != expected_counter {
                    log::warn!(
                        "Timestamp for unrelated packet (expected = {}, actual = {})",
                        expected_counter,
                        error.ee_data,
                    );
                    return Ok(None);
                }
            }

            ControlMessage::Other(msg) => {
                log::warn!(
                    "unexpected message on the MSG_ERRQUEUE (level = {}, type = {})",
                    msg.cmsg_level,
                    msg.cmsg_type,
                );
            }
        }
    }

    Ok(send_ts.map(libc_timespec_into_instant))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, UdpSocket};

    use statime::time::Duration;

    use super::*;
    use crate::clock::RawLinuxClock;

    fn new_timestamped(p1: u16, p2: u16) -> TimestampedUdpSocket {
        let mode = TimestampingMode::Software;

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, p1)).unwrap();
        socket.connect((Ipv4Addr::LOCALHOST, p2)).unwrap();
        socket.set_nonblocking(true).unwrap();

        TimestampedUdpSocket::from_udp_socket(socket, mode).unwrap()
    }

    async fn timestamping_reasonable(p1: u16, p2: u16) {
        let (mut a, b) = (new_timestamped(p1, p2), new_timestamped(p2, p1));
        let target = b.io.get_ref().local_addr().unwrap();

        tokio::spawn(async move {
            a.send(&[1; 48], target).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            a.send(&[2; 48], target).await.unwrap();
        });

        let clock = LinuxClock::new(RawLinuxClock::get_realtime_clock());

        let mut buf = [0; 48];
        let r1 = b.recv(&clock, &mut buf).await.unwrap();
        let r2 = b.recv(&clock, &mut buf).await.unwrap();

        assert_eq!(r1.bytes_read, 48);
        assert_eq!(r1.bytes_read, 48);

        let t1 = r1.timestamp;
        let t2 = r2.timestamp;
        let delta = t2 - t1;

        let lower = Duration::from_millis(150); // 0.15s
        let upper = Duration::from_millis(250); // 0.25s

        assert!(delta > lower && delta < upper);
    }

    #[tokio::test]
    async fn timestamping_reasonable_so_timestamping() {
        timestamping_reasonable(8000, 8001).await
    }

    #[tokio::test]
    async fn test_software_send_timestamp() {
        let (p1, p2) = (8002, 8003);

        let (mut a, b) = (new_timestamped(p1, p2), new_timestamped(p2, p1));
        let target = b.io.get_ref().local_addr().unwrap();

        let clock = LinuxClock::new(RawLinuxClock::get_realtime_clock());

        let tsend = a.send(&[1; 48], target).await.unwrap();
        let mut buf = [0; 48];
        let trecv = b.recv(&clock, &mut buf).await.unwrap();

        let tsend = tsend.unwrap();
        let trecv = trecv.timestamp;
        let delta = trecv - tsend;

        let tolerance = Duration::from_millis(200); // 0.20s
        assert!(delta.abs() < tolerance);
    }
}
