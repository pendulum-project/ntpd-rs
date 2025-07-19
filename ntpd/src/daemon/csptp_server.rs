use std::{io::Cursor, sync::Arc, time::Duration};

use ntp_proto::{CsptpPacket, KeySet, NtpClock, SystemSnapshot};
use statime::datastructures::common::WireTimestamp;
use timestamped_socket::socket::{RecvResult, open_ip};
use tokio::task::JoinHandle;
use tracing::{Instrument, Span, debug, instrument, warn};

use crate::daemon::config::CsptpServerConfig;

const MAX_PACKET_SIZE: usize = 1024;

pub struct CsptpServerTask<C: 'static + NtpClock + Send> {
    config: CsptpServerConfig,
    network_wait_period: std::time::Duration,
    system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    server: CsptpServer<C>,
}

impl<C: 'static + NtpClock + Send> CsptpServerTask<C> {
    #[instrument(level = tracing::Level::ERROR, name = "CSPTP Server", skip_all, fields(address = debug(config.listen)))]
    pub fn spawn(
        config: CsptpServerConfig,
        mut system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
        mut keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
        clock: C,
        network_wait_period: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(
            (async move {
                let server = CsptpServer::new(
                    config.clone().into(),
                    clock,
                    *system_receiver.borrow_and_update(),
                    keyset.borrow_and_update().clone(),
                );

                let mut process = CsptpServerTask {
                    config,
                    network_wait_period,
                    system_receiver,
                    keyset,
                    server,
                };

                process.serve().await;
            })
            .instrument(Span::current()),
        )
    }

    async fn serve(&mut self) {
        let mut cur_socket = None;
        loop {
            // open socket if it is not already open
            let socket = match &mut cur_socket {
                Some(socket) => socket,
                None => {
                    let new_socket = loop {
                        let socket_res = open_ip(
                            self.config.listen,
                            timestamped_socket::socket::GeneralTimestampMode::SoftwareRecv,
                        );

                        match socket_res {
                            Ok(socket) => break socket,
                            Err(error) => {
                                warn!(?error, ?self.config.listen, "Could not open server socket");
                                tokio::time::sleep(self.network_wait_period).await;
                            }
                        }
                    };

                    // system and keyset may now be wildly out of date, ensure they are always updated.
                    self.server
                        .update_system(*self.system_receiver.borrow_and_update());
                    self.server
                        .update_keyset(self.keyset.borrow_and_update().clone());

                    cur_socket.insert(new_socket)
                }
            };

            let mut buf = [0_u8; MAX_PACKET_SIZE];
            tokio::select! {
                recv_res = socket.recv(&mut buf) => {
                    match recv_res {
                        Ok(RecvResult {
                            bytes_read: length,
                            remote_addr: source_addr,
                            timestamp: Some(timestamp),
                        }) => {
                            let mut send_buf = [0u8; MAX_PACKET_SIZE];
                            if let Some(buf) = self.server.respond(&mut send_buf, &buf[..length], timestamp) {
                                let _ = socket.send_to(buf, source_addr).await;
                            }
                        }
                        Ok(_) => {
                            debug!("received a packet without a timestamp");
                        }
                        Err(receive_error) => {
                            warn!(?receive_error, "could not receive packet");

                            // For a server, we only trigger NetworkGone restarts
                            // on ENETDOWN. ENETUNREACH, EHOSTDOWN and EHOSTUNREACH
                            // do not signal restart-worthy conditions for the a
                            // server (they essentially indicate problems with the
                            // remote network/host, which is not relevant for a server).
                            // Furthermore, they can conceivably be triggered by a
                            // malicious third party, and triggering restart on them
                            // would then result in a denial-of-service.
                            if matches!(receive_error.raw_os_error(), Some(libc::ENETDOWN)) {
                                cur_socket = None;
                            }
                        }
                    }
                },
                _ = self.system_receiver.changed(), if self.system_receiver.has_changed().is_ok() => {
                    self.server.update_system(*self.system_receiver.borrow_and_update());
                }
                _ = self.keyset.changed(), if self.keyset.has_changed().is_ok() => {
                    self.server.update_keyset(self.keyset.borrow_and_update().clone());
                }
            }
        }
    }
}

pub struct CsptpServer<C> {
    config: CsptpServerConfig,
    clock: C,
    system: SystemSnapshot,
    keyset: Arc<KeySet>,
}

impl<C> CsptpServer<C> {
    /// Create a new server
    pub fn new(
        config: CsptpServerConfig,
        clock: C,
        system: SystemSnapshot,
        keyset: Arc<KeySet>,
    ) -> Self {
        Self {
            config,
            clock,
            system,
            keyset,
        }
    }

    /// Provide the server with the latest [`SystemSnapshot`]
    pub fn update_system(&mut self, system: SystemSnapshot) {
        self.system = system;
    }

    /// Provide the server with a new [`KeySet`]
    pub fn update_keyset(&mut self, keyset: Arc<KeySet>) {
        self.keyset = keyset;
    }
}

impl<C: NtpClock> CsptpServer<C> {
    fn respond<'a>(
        &self,
        buffer: &'a mut [u8],
        request: &[u8],
        timestamp: timestamped_socket::socket::Timestamp,
    ) -> Option<&'a [u8]> {
        let packet = CsptpPacket::deserialize(request).ok()?;
        if packet.get_origin_timestamp().is_none() || packet.get_csptp_request_flags().is_none() {
            return None;
        }

        let mut tlvbuffer = [0u8; MAX_PACKET_SIZE];
        let receive_timestamp = WireTimestamp {
            seconds: (timestamp.seconds + 37) as _,
            nanos: timestamp.nanos,
        };
        let send_time = self.clock.now().ok()?;
        let send_timestamp = send_time.to_statime();
        let response = CsptpPacket::timestamp_response(
            &mut tlvbuffer,
            packet,
            receive_timestamp,
            send_timestamp,
        );

        let mut cursor = Cursor::new(buffer);
        response.serialize(&mut cursor).ok()?;
        let size = cursor.position() as usize;
        Some(&cursor.into_inner()[..size])
    }
}
