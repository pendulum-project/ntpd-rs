use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use ntp_proto::{
    KeySet, NtpClock, Server, ServerReason, ServerResponse, ServerStatHandler, SystemSnapshot,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use timestamped_socket::socket::{open_ip, RecvResult};
use tokio::task::JoinHandle;
use tracing::{debug, instrument, warn, Instrument, Span};

use super::{config::ServerConfig, util::convert_net_timestamp};

// Maximum size of udp packet we handle
const MAX_PACKET_SIZE: usize = 1024;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub received_packets: Counter,
    pub accepted_packets: Counter,
    pub denied_packets: Counter,
    pub ignored_packets: Counter,
    pub rate_limited_packets: Counter,
    pub response_send_errors: Counter,
    pub nts_received_packets: Counter,
    pub nts_accepted_packets: Counter,
    pub nts_denied_packets: Counter,
    pub nts_rate_limited_packets: Counter,
    pub nts_nak_packets: Counter,
}

impl ServerStatHandler for ServerStats {
    fn register(
        &mut self,
        _version: u8,
        nts: bool,
        reason: ServerReason,
        response: ServerResponse,
    ) {
        self.received_packets.inc();

        match (response, reason) {
            (ServerResponse::ProvideTime, _) => self.accepted_packets.inc(),
            (ServerResponse::Ignore, ServerReason::RateLimit) => self.rate_limited_packets.inc(),
            (ServerResponse::Ignore, _) => self.ignored_packets.inc(),
            (ServerResponse::Deny, _) => self.denied_packets.inc(),
            (ServerResponse::NTSNak, _) => self.nts_nak_packets.inc(),
        }

        if nts {
            self.nts_received_packets.inc();
            match (response, reason) {
                (ServerResponse::ProvideTime, _) => self.nts_accepted_packets.inc(),
                (ServerResponse::Deny, _) => self.nts_denied_packets.inc(),
                (ServerResponse::Ignore, ServerReason::RateLimit) => {
                    self.nts_rate_limited_packets.inc();
                }
                _ => { /* counted above */ }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Counter {
    value: Arc<AtomicU64>,
}

impl Counter {
    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.as_ref().load(Ordering::Relaxed)
    }
}

impl Serialize for Counter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D>(deserializer: D) -> Result<Counter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Arc::new(Deserialize::deserialize(deserializer)?);
        Ok(Counter { value })
    }
}

pub struct ServerTask<C: 'static + NtpClock + Send> {
    config: ServerConfig,
    network_wait_period: std::time::Duration,
    system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    server: Server<C>,
    stats: ServerStats,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    #[instrument(level = tracing::Level::ERROR, name = "Ntp Server", skip_all, fields(address = debug(config.listen)))]
    pub fn spawn(
        config: ServerConfig,
        stats: ServerStats,
        mut system_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
        mut keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
        clock: C,
        network_wait_period: Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(
            (async move {
                let server = Server::new(
                    config.clone().into(),
                    clock,
                    *system_receiver.borrow_and_update(),
                    keyset.borrow_and_update().clone(),
                );

                let mut process = ServerTask {
                    config,
                    network_wait_period,
                    system_receiver,
                    keyset,
                    server,
                    stats,
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
                            match self.server.handle(source_addr.ip(), convert_net_timestamp(timestamp), &buf[..length], &mut send_buf[..length], &mut self.stats) {
                                ntp_proto::ServerAction::Ignore => { /* explicitly do nothing */ },
                                ntp_proto::ServerAction::Respond { message } => {
                                    if let Err(send_err) = socket.send_to(message, source_addr).await {
                                        self.stats.response_send_errors.inc();
                                        debug!(error=?send_err, "Could not send response packet");
                                    }
                                },
                            }
                        }
                        Ok(_) => {
                            debug!("received a packet without a timestamp");
                            self.stats.register(0, false, ServerReason::InternalError, ServerResponse::Ignore);
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

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, io::Cursor};

    use ntp_proto::{
        KeySetProvider, NoCipher, NtpDuration, NtpLeapIndicator, NtpPacket, NtpTimestamp,
        PollIntervalLimits,
    };
    use timestamped_socket::socket::GeneralTimestampMode;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {
        time: NtpTimestamp,
    }

    impl NtpClock for TestClock {
        type Error = Infallible;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Ok(self.time)
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by source");
        }
    }

    fn serialize_packet_unencrypted(send_packet: &NtpPacket) -> Vec<u8> {
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        send_packet.serialize(&mut cursor, &NoCipher, None).unwrap();

        let end = cursor.position() as usize;
        buf.truncate(end);
        buf
    }

    #[tokio::test]
    async fn test_server_serves() {
        let config = ServerConfig::try_from("127.0.0.1:9000").unwrap();

        let clock = TestClock {
            time: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 1000),
        };
        let (_, system_snapshots) = tokio::sync::watch::channel(SystemSnapshot::default());
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let join = ServerTask::spawn(
            config,
            ServerStats::default(),
            system_snapshots,
            keyset,
            clock,
            Duration::from_secs(0),
        );

        let socket = open_ip(
            "127.0.0.1:9001".parse().unwrap(),
            GeneralTimestampMode::SoftwareRecv,
        )
        .unwrap();
        let mut socket = socket.connect("127.0.0.1:9000".parse().unwrap()).unwrap();
        let (packet, id) = NtpPacket::poll_message(PollIntervalLimits::default().min);

        let serialized = serialize_packet_unencrypted(&packet);
        socket.send(&serialized).await.unwrap();

        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpPacket::deserialize(&buf, &NoCipher).unwrap().0;
        assert_ne!(packet.stratum(), 0);
        assert!(packet.valid_server_response(id, false));

        join.abort();
    }
}
