use std::net::SocketAddr;

use ntp_proto::{NtpHeader, NtpTimestamp, ReferenceId};
use ntp_udp::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{instrument, warn};

pub struct ServerTask {
    socket: UdpSocket,
}

impl ServerTask {
    pub fn spawn(addr: SocketAddr, network_wait_period: std::time::Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let socket = loop {
                match UdpSocket::new::<_, SocketAddr>(addr, None).await {
                    Ok(socket) => break socket,
                    Err(error) => {
                        warn!(?error, "Could not open server socket");
                        tokio::time::sleep(network_wait_period).await;
                    }
                }
            };

            // Unwrap should be safe because we know the socket was bound to a local addres just before
            let _our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());

            let mut process = ServerTask { socket };

            process.serve().await
        })
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.socket.as_ref().local_addr().unwrap()),
    ))]
    async fn serve(&mut self) {
        loop {
            let mut buf = [0_u8; 48];
            let recv_res = self.socket.recv(&mut buf).await;
            match accept_packet(recv_res, &buf) {
                AcceptResult::Accept(packet, peer_addr, _recv_timestamp) => {
                    // TODO: not be an echo server
                    if let Err(send_err) = self.socket.send_to(&packet.serialize(), peer_addr).await
                    {
                        warn!(error=?send_err, "Could not send response packet");
                    }
                }
                AcceptResult::NetworkGone => {
                    // TODO: handle network failures
                    break;
                }
                AcceptResult::Ignore => {}
            }
        }
    }
}

enum AcceptResult {
    Accept(NtpHeader, SocketAddr, NtpTimestamp),
    Ignore,
    NetworkGone,
}

fn accept_packet(
    result: Result<(usize, SocketAddr, Option<NtpTimestamp>), std::io::Error>,
    buf: &[u8; 48],
) -> AcceptResult {
    match result {
        Ok((size, peer_addr, Some(recv_timestamp))) => {
            // Note: packets are allowed to be bigger when including extensions.
            // we don't expect them, but the server may still send them. The
            // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
            // Messages of fewer than 48 bytes are skipped entirely
            if size < 48 {
                warn!(expected = 48, actual = size, "received packet is too small");

                AcceptResult::Ignore
            } else {
                match NtpHeader::deserialize(buf) {
                    Ok(packet) => AcceptResult::Accept(packet, peer_addr, recv_timestamp),
                    Err(e) => {
                        warn!("received invalid packet: {}", e);
                        AcceptResult::Ignore
                    }
                }
            }
        }
        Ok((size, _, None)) => {
            warn!(?size, "received a packet without a timestamp");

            AcceptResult::Ignore
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive packet");

            match receive_error.raw_os_error() {
                Some(libc::EHOSTDOWN)
                | Some(libc::EHOSTUNREACH)
                | Some(libc::ENETDOWN)
                | Some(libc::ENETUNREACH) => AcceptResult::NetworkGone,
                _ => AcceptResult::Ignore,
            }
        }
    }
}
