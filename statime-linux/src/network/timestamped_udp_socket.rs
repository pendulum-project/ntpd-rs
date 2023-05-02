#![forbid(unsafe_code)]

use statime::{clock::Clock, network::NetworkPacket, time::Instant};
use std::io::{self, ErrorKind};
use std::{net::SocketAddr, os::unix::prelude::RawFd};
use tokio::io::{unix::AsyncFd, Interest};

use crate::clock::{libc_timespec_into_instant, LinuxClock};

use super::control_message::{control_message_space, ControlMessage, MessageQueue};
use super::linux::TimestampingMode;
use super::raw_udp_socket::{exceptional_condition_fd, receive_message, set_timestamping_options};

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

    pub async fn recv(&self, clock: &LinuxClock) -> std::io::Result<NetworkPacket> {
        let receiver = |inner: &std::net::UdpSocket| recv_with_timestamp(inner, clock);
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
        // the send timestamp may never come set a very short timeout to prevent hanging forever.
        // We automatically fall back to a less accurate timestamp when this function returns None
        let timeout = std::time::Duration::from_millis(10);

        let fetch = self.fetch_send_timestamp_help(expected_counter);
        if let Ok(send_timestamp) = tokio::time::timeout(timeout, fetch).await {
            Ok(Some(send_timestamp?))
        } else {
            log::warn!("Packet without timestamp (waiting for timestamp timed out)");
            Ok(None)
        }
    }

    async fn fetch_send_timestamp_help(&self, expected_counter: u32) -> std::io::Result<Instant> {
        log::trace!("waiting for timestamp socket to become readable to fetch a send timestamp");

        // Send timestamps are sent to the udp socket's error queue. Sadly, tokio does not
        // currently support awaiting whether there is something in the error queue
        // see https://github.com/tokio-rs/tokio/issues/4885.
        //
        // Therefore, we manually configure an extra file descriptor to listen for POLLPRI on
        // the main udp socket. This `exceptional_condition` file descriptor becomes readable
        // when there is something in the error queue.

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

fn recv_with_timestamp(
    tc_socket: &std::net::UdpSocket,
    clock: &LinuxClock,
) -> std::io::Result<NetworkPacket> {
    let mut read_buf = [0u8; 2048];
    let mut control_buf = [0; control_message_space::<[libc::timespec; 3]>()];

    // loops for when we receive an interrupt during the recv
    let (bytes_read, control_messages, _) = receive_message(
        tc_socket,
        &mut read_buf,
        &mut control_buf,
        MessageQueue::Normal,
    )?;

    let mut timestamp = clock.now();

    // Loops through the control messages, but we should only get a single message in practice
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

    let data = read_buf[..bytes_read as usize]
        .try_into()
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "too long"))?;

    Ok(NetworkPacket { data, timestamp })
}

fn fetch_send_timestamp_help(
    socket: &std::net::UdpSocket,
    expected_counter: u32,
) -> io::Result<Option<Instant>> {
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
                    log::warn!(
                            "error message on the MSG_ERRQUEUE: expected message {}, it has error code {}",
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

    Ok(send_ts.map(|ts| libc_timespec_into_instant(ts)))
}
