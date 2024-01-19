use super::server::ServerStats;
use super::sockets::create_unix_socket_with_permissions;
use super::spawn::PeerId;
use super::system::ServerData;
use ntp_proto::{ObservablePeerTimedata, PollInterval, SystemSnapshot};
use std::os::unix::fs::PermissionsExt;
use std::{net::SocketAddr, time::Instant};
use tokio::task::JoinHandle;
use tracing::warn;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub program: ProgramData,
    pub system: SystemSnapshot,
    pub sources: Vec<ObservablePeerState>,
    pub servers: Vec<ObservableServerState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramData {
    pub version: String,
    pub build_commit: String,
    pub build_commit_date: String,
    pub uptime_seconds: f64,
}

impl ProgramData {
    pub fn with_uptime(uptime_seconds: f64) -> ProgramData {
        ProgramData {
            uptime_seconds,
            ..Default::default()
        }
    }
}

impl Default for ProgramData {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build_commit: env!("NTPD_RS_GIT_REV").to_owned(),
            build_commit_date: env!("NTPD_RS_GIT_DATE").to_owned(),
            uptime_seconds: 0.0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableServerState {
    pub address: SocketAddr,
    pub stats: ServerStats,
}

impl From<&ServerData> for ObservableServerState {
    fn from(data: &ServerData) -> Self {
        ObservableServerState {
            address: data.config.listen,
            stats: data.stats.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ObservablePeerState {
    Nothing,
    Observable(ObservedPeerState),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObservedPeerState {
    #[serde(flatten)]
    pub timedata: ObservablePeerTimedata,
    pub unanswered_polls: u32,
    pub poll_interval: PollInterval,
    pub name: String,
    pub address: String,
    pub id: PeerId,
}

pub async fn spawn(
    config: &super::config::ObservabilityConfig,
    peers_reader: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> JoinHandle<std::io::Result<()>> {
    let config = config.clone();
    tokio::spawn(async move {
        let result = observer(config, peers_reader, server_reader, system_reader).await;
        if let Err(ref e) = result {
            warn!("Abnormal termination of the state observer: {e}");
            warn!("The state observer will not be available");
        }
        result
    })
}

async fn observer(
    config: super::config::ObservabilityConfig,
    peers_reader: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> std::io::Result<()> {
    let start_time = Instant::now();

    let path = match config.observation_path {
        Some(path) => path,
        None => return Ok(()),
    };

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions =
        PermissionsExt::from_mode(config.observation_permissions);

    let peers_listener = create_unix_socket_with_permissions(&path, permissions)?;

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let observe = ObservableState {
            program: ProgramData::with_uptime(start_time.elapsed().as_secs_f64()),
            sources: peers_reader.borrow().to_owned(),
            system: *system_reader.borrow(),
            servers: server_reader.borrow().iter().map(|s| s.into()).collect(),
        };

        super::sockets::write_json(&mut stream, &observe).await?;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "unstable_ntpv5")]
    use rand::thread_rng;
    use std::{borrow::BorrowMut, time::Duration};

    #[cfg(feature = "unstable_ntpv5")]
    use ntp_proto::v5::{BloomFilter, ServerId};
    use ntp_proto::{
        NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollIntervalLimits, Reach,
        ReferenceId, TimeSnapshot,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            Ok(NtpTimestamp::default())
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            Ok(NtpTimestamp::default())
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_observation() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-2");
        let config = super::super::config::ObservabilityConfig {
            log_level: None,
            observation_path: Some(path.clone()),
            observation_permissions: 0o700,
            ..Default::default()
        };

        let (_, peers_reader) = tokio::sync::watch::channel(vec![
            ObservablePeerState::Nothing,
            ObservablePeerState::Nothing,
            ObservablePeerState::Observable(ObservedPeerState {
                timedata: Default::default(),
                unanswered_polls: Reach::default().unanswered_polls(),
                poll_interval: PollIntervalLimits::default().min,
                name: "127.0.0.3:123".into(),
                address: "127.0.0.3:123".into(),
                id: PeerId::new(),
            }),
        ]);

        let (_, servers_reader) = tokio::sync::watch::channel(vec![]);

        let (_, system_reader) = tokio::sync::watch::channel(SystemSnapshot {
            stratum: 1,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot {
                poll_interval: PollIntervalLimits::default().min,
                precision: NtpDuration::from_seconds(1e-3),
                root_delay: NtpDuration::ZERO,
                root_dispersion: NtpDuration::ZERO,
                leap_indicator: NtpLeapIndicator::Leap59,
                accumulated_steps: NtpDuration::ZERO,
            },
            #[cfg(feature = "unstable_ntpv5")]
            bloom_filter: BloomFilter::new(),
            #[cfg(feature = "unstable_ntpv5")]
            server_id: ServerId::new(&mut thread_rng()),
        });

        let handle = tokio::spawn(async move {
            observer(config, peers_reader, servers_reader, system_reader)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();

        let mut buf = vec![];
        while reader.read_buf(&mut buf).await.unwrap() != 0 {}
        let result: ObservableState = serde_json::from_slice(&buf).unwrap();

        // Deal with randomized order
        let mut count = 0;
        for peer in &result.sources {
            if matches!(peer, ObservablePeerState::Observable { .. }) {
                count += 1;
            }
        }
        assert_eq!(count, 1);

        handle.abort();
    }

    #[tokio::test]
    async fn test_block_during_read() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-3");
        let config = super::super::config::ObservabilityConfig {
            log_level: None,
            observation_path: Some(path.clone()),
            observation_permissions: 0o700,
            ..Default::default()
        };

        let (mut peers_writer, peers_reader) = tokio::sync::watch::channel(vec![
            ObservablePeerState::Nothing,
            ObservablePeerState::Nothing,
            ObservablePeerState::Observable(ObservedPeerState {
                timedata: Default::default(),
                unanswered_polls: Reach::default().unanswered_polls(),
                poll_interval: PollIntervalLimits::default().min,
                name: "127.0.0.3:123".into(),
                address: "127.0.0.3:123".into(),
                id: PeerId::new(),
            }),
        ]);

        let (mut server_writer, servers_reader) = tokio::sync::watch::channel(vec![]);

        let (mut system_writer, system_reader) = tokio::sync::watch::channel(SystemSnapshot {
            stratum: 1,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot {
                poll_interval: PollIntervalLimits::default().min,
                precision: NtpDuration::from_seconds(1e-3),
                root_delay: NtpDuration::ZERO,
                root_dispersion: NtpDuration::ZERO,
                leap_indicator: NtpLeapIndicator::Leap59,
                accumulated_steps: NtpDuration::ZERO,
            },
            #[cfg(feature = "unstable_ntpv5")]
            bloom_filter: BloomFilter::new(),
            #[cfg(feature = "unstable_ntpv5")]
            server_id: ServerId::new(&mut thread_rng()),
        });

        let handle = tokio::spawn(async move {
            observer(config, peers_reader, servers_reader, system_reader)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();

        // We do a small partial read of the data to test that whatever
        // happens, the observer doesnt keep a lock alive on either of
        // of the RwLocks.
        let mut buf = [0_u8; 12];
        let mut bufref: &mut [u8] = &mut buf;
        reader.read_buf(&mut bufref).await.unwrap();

        // Ensure none of the locks is held long term
        let _ = system_writer.borrow_mut();
        let _ = peers_writer.borrow_mut();
        let _ = server_writer.borrow_mut();

        handle.abort();
    }
}
