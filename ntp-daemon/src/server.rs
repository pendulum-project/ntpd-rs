use std::{net::SocketAddr, sync::Arc};

use ntp_proto::{
    NtpAssociationMode, NtpClock, NtpHeader, NtpTimestamp, ReferenceId, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{instrument, warn};

pub struct ServerTask<C: 'static + NtpClock + Send> {
    socket: UdpSocket,
    system: Arc<RwLock<SystemSnapshot>>,
    clock: C,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        addr: SocketAddr,
        system: Arc<RwLock<SystemSnapshot>>,
        clock: C,
        network_wait_period: std::time::Duration,
    ) -> JoinHandle<()> {
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

            let mut process = ServerTask {
                socket,
                system,
                clock,
            };

            process.serve().await
        })
    }

    async fn generate_response(
        &mut self,
        input: NtpHeader,
        recv_timestamp: NtpTimestamp,
    ) -> NtpHeader {
        let system = self.system.read().await;
        let mut response = NtpHeader::new();
        response.mode = NtpAssociationMode::Server;
        response.stratum = system.stratum;
        response.origin_timestamp = input.transmit_timestamp;
        response.receive_timestamp = recv_timestamp;
        response.reference_id = system.reference_id;
        response.poll = input.poll;
        response.precision = system.precision.log2();
        response.root_delay = system.root_delay;
        response.root_dispersion = system.root_dispersion;
        response.transmit_timestamp = self.clock.now().expect("Failed to read time");

        response
    }

    #[instrument(level = "debug", skip(self), fields(
        addr = debug(self.socket.as_ref().local_addr().unwrap()),
    ))]
    async fn serve(&mut self) {
        loop {
            let mut buf = [0_u8; 48];
            let recv_res = self.socket.recv(&mut buf).await;
            match accept_packet(recv_res, &buf) {
                AcceptResult::Accept(packet, peer_addr, recv_timestamp) => {
                    let response = self.generate_response(packet, recv_timestamp).await;

                    if let Err(send_err) =
                        self.socket.send_to(&response.serialize(), peer_addr).await
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
                    Ok(packet) => match packet.mode {
                        NtpAssociationMode::Client => {
                            AcceptResult::Accept(packet, peer_addr, recv_timestamp)
                        }
                        _ => AcceptResult::Ignore,
                    },
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
