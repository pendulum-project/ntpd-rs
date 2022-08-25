use std::{net::SocketAddr, sync::Arc};

use ntp_proto::{
    NtpAssociationMode, NtpClock, NtpHeader, NtpTimestamp, ReferenceId, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{error, instrument, trace, warn};

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
                match UdpSocket::server(addr).await {
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
        NtpHeader {
            mode: NtpAssociationMode::Server,
            stratum: system.stratum,
            origin_timestamp: input.transmit_timestamp,
            receive_timestamp: recv_timestamp,
            reference_id: system.reference_id,
            poll: input.poll,
            precision: system.precision.log2(),
            root_delay: system.root_delay,
            root_dispersion: system.root_dispersion,
            // Timestamp must be last to make it as accurate as possible.
            transmit_timestamp: self.clock.now().expect("Failed to read time"),
            ..NtpHeader::new()
        }
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
                    error!("Server connection gone");
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
                            trace!("NTP client request accepted from {}", peer_addr);
                            AcceptResult::Accept(packet, peer_addr, recv_timestamp)
                        }
                        _ => {
                            trace!(
                                "NTP packet with unkown mode {:?} ignored from {}",
                                packet.mode,
                                peer_addr
                            );
                            AcceptResult::Ignore
                        }
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
                // For a server, we only trigger NetworkGone restarts
                // on ENETDOWN. ENETUNREACH, EHOSTDOWN and EHOSTUNREACH
                // do not signal restart-worthy conditions for the a
                // server (they essentially indicate problems with the
                // remote network/host, which is not relevant for a server).
                // Furthermore, they can conceivably be triggered by a
                // malicious third party, and triggering restart on them
                // would then result in a denial-of-service.
                Some(libc::ENETDOWN) => AcceptResult::NetworkGone,
                _ => AcceptResult::Ignore,
            }
        }
    }
}
