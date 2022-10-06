use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use ntp_proto::{
    NtpAssociationMode, NtpClock, NtpHeader, NtpTimestamp, ReferenceId, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{error, info, instrument, trace, warn};

use crate::config::{FilterAction, ServerConfig};

pub struct ServerTask<C: 'static + NtpClock + Send> {
    config: Arc<ServerConfig>,
    network_wait_period: std::time::Duration,
    system: Arc<RwLock<SystemSnapshot>>,
    clock: C,
}

#[derive(Debug)]
enum AcceptResult {
    Accept(NtpHeader, SocketAddr, NtpTimestamp),
    Ignore,
    Deny(NtpHeader, SocketAddr),
    NetworkGone,
}

impl<C: 'static + NtpClock + Send> ServerTask<C> {
    pub fn spawn(
        config: Arc<ServerConfig>,
        system: Arc<RwLock<SystemSnapshot>>,
        clock: C,
        network_wait_period: std::time::Duration,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut process = ServerTask {
                config,
                network_wait_period,
                system,
                clock,
            };

            process.serve().await
        })
    }

    fn filter(&self, addr: &IpAddr) -> Option<FilterAction> {
        if self.config.denylist.is_in(addr) {
            // First apply denylist
            Some(self.config.denylist_action)
        } else if !self.config.allowlist.is_in(addr) {
            // Then allowlist
            Some(self.config.allowlist_action)
        } else {
            None
        }
    }

    fn generate_deny(&self, input: NtpHeader) -> NtpHeader {
        NtpHeader {
            mode: NtpAssociationMode::Server,
            stratum: 0,
            reference_id: ReferenceId::KISS_DENY,
            origin_timestamp: input.transmit_timestamp,
            ..NtpHeader::new()
        }
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
        addr = debug(self.config.addr),
    ))]
    async fn serve(&mut self) {
        let mut cur_socket = None;
        loop {
            let socket = if let Some(ref socket) = cur_socket {
                socket
            } else {
                cur_socket = Some(loop {
                    match UdpSocket::server(self.config.addr).await {
                        Ok(socket) => break socket,
                        Err(error) => {
                            warn!(?error, "Could not open server socket");
                            tokio::time::sleep(self.network_wait_period).await;
                        }
                    }
                });
                cur_socket.as_ref().unwrap()
            };

            let mut buf = [0_u8; 48];
            let recv_res = socket.recv(&mut buf).await;
            let accept_result = self.accept_packet(recv_res, &buf);
            match accept_result {
                AcceptResult::Accept(packet, peer_addr, recv_timestamp) => {
                    let response = self.generate_response(packet, recv_timestamp).await;

                    if let Err(send_err) = socket.send_to(&response.serialize(), peer_addr).await {
                        warn!(error=?send_err, "Could not send response packet");
                    }
                }
                AcceptResult::Deny(packet, peer_addr) => {
                    let response = self.generate_deny(packet);
                    if let Err(send_err) = socket.send_to(&response.serialize(), peer_addr).await {
                        warn!(error=?send_err, "Could not send deny packet");
                    }
                }
                AcceptResult::NetworkGone => {
                    error!("Server connection gone");
                    cur_socket = None;
                    continue;
                }
                AcceptResult::Ignore => {}
            }
        }
    }

    fn accept_packet(
        &self,
        result: Result<(usize, SocketAddr, Option<NtpTimestamp>), std::io::Error>,
        buf: &[u8; 48],
    ) -> AcceptResult {
        match result {
            Ok((size, peer_addr, Some(recv_timestamp))) if size >= 48 => {
                // Note: packets are allowed to be bigger when including extensions.
                // we don't expect them, but the client may still send them. The
                // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
                // Messages of fewer than 48 bytes are skipped entirely
                match self.filter(&peer_addr.ip()) {
                    Some(FilterAction::Deny) => {
                        match self.accept_data(buf, peer_addr, recv_timestamp) {
                            // We should send deny messages only to reasonable requests
                            // otherwise two servers could end up in a loop of sending
                            // deny's to each other.
                            AcceptResult::Accept(packet, addr, _) => {
                                AcceptResult::Deny(packet, addr)
                            }
                            v => v,
                        }
                    }
                    Some(FilterAction::Ignore) => AcceptResult::Ignore,
                    None => self.accept_data(buf, peer_addr, recv_timestamp),
                }
            }
            Ok((size, _, Some(_))) => {
                info!(expected = 48, actual = size, "received packet is too small");

                AcceptResult::Ignore
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

    fn accept_data(
        &self,
        buf: &[u8; 48],
        peer_addr: SocketAddr,
        recv_timestamp: NtpTimestamp,
    ) -> AcceptResult {
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
                info!("received invalid packet: {}", e);
                AcceptResult::Ignore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntp_proto::{NtpDuration, NtpLeapIndicator, PollInterval};

    use crate::ipfilter::IpFilter;

    use super::*;

    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur =
                std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_freq(&self, _freq: f64) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn update_clock(
            &self,
            _offset: NtpDuration,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
            _poll_interval: PollInterval,
            _leap_status: NtpLeapIndicator,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }
    }

    #[tokio::test]
    async fn test_server_filter_allow_ok() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9000".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Ignore,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9001".parse().unwrap(),
            "127.0.0.1:9000".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpHeader::deserialize(&buf).unwrap();
        assert_ne!(packet.stratum, 0);

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_allow_deny() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9002".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["128.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Deny,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9003".parse().unwrap(),
            "127.0.0.1:9002".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpHeader::deserialize(&buf).unwrap();
        assert_eq!(packet.stratum, 0);
        assert_eq!(packet.reference_id, ReferenceId::KISS_DENY);

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_allow_ignore() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9004".parse().unwrap(),
            denylist: IpFilter::none(),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::new(&["128.0.0.0/24".parse().unwrap()]),
            allowlist_action: FilterAction::Ignore,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9005".parse().unwrap(),
            "127.0.0.1:9004".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        let res = tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf)).await;
        assert!(res.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_ok() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9006".parse().unwrap(),
            denylist: IpFilter::new(&["192.168.0.0/16".parse().unwrap()]),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9007".parse().unwrap(),
            "127.0.0.1:9006".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpHeader::deserialize(&buf).unwrap();
        assert_ne!(packet.stratum, 0);

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_deny() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9008".parse().unwrap(),
            denylist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            denylist_action: FilterAction::Deny,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9009".parse().unwrap(),
            "127.0.0.1:9008".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = NtpHeader::deserialize(&buf).unwrap();
        assert_eq!(packet.stratum, 0);
        assert_eq!(packet.reference_id, ReferenceId::KISS_DENY);

        server.abort();
    }

    #[tokio::test]
    async fn test_server_filter_deny_ignore() {
        let config = Arc::new(ServerConfig {
            addr: "127.0.0.1:9010".parse().unwrap(),
            denylist: IpFilter::new(&["127.0.0.0/24".parse().unwrap()]),
            denylist_action: FilterAction::Ignore,
            allowlist: IpFilter::all(),
            allowlist_action: FilterAction::Ignore,
        });
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let clock = TestClock {};

        let server = ServerTask::spawn(config, system_snapshots, clock, Duration::from_secs(1));

        let mut socket = UdpSocket::client(
            "127.0.0.1:9011".parse().unwrap(),
            "127.0.0.1:9010".parse().unwrap(),
        )
        .await
        .unwrap();
        let packet = NtpHeader {
            mode: NtpAssociationMode::Client,
            ..NtpHeader::new()
        };

        socket.send(&packet.serialize()).await.unwrap();
        let mut buf = [0; 48];
        let res = tokio::time::timeout(Duration::from_millis(10), socket.recv(&mut buf)).await;
        assert!(res.is_err());

        server.abort();
    }
}
