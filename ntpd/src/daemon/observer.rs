use super::server::ServerStats;
use super::sockets::create_unix_socket_with_permissions;
use super::spawn::SourceId;
use super::system::ServerData;
use libc::{ECONNABORTED, EMFILE, ENFILE, ENOBUFS, ENOMEM};
use ntp_proto::{ObservableSourceState, SystemSnapshot};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::{net::SocketAddr, time::Instant};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub program: ProgramData,
    pub system: SystemSnapshot,
    pub sources: Vec<ObservableSourceState<SourceId>>,
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

pub async fn spawn(
    config: &super::config::ObservabilityConfig,
    sources_reader: Arc<std::sync::RwLock<HashMap<SourceId, ObservableSourceState<SourceId>>>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> JoinHandle<std::io::Result<()>> {
    let config = config.clone();
    tokio::spawn(async move {
        let result = observer(config, sources_reader, server_reader, system_reader).await;
        if let Err(ref e) = result {
            warn!("Abnormal termination of the state observer: {e}");
            warn!("The state observer will not be available");
        }
        result
    })
}

async fn observer(
    config: super::config::ObservabilityConfig,
    sources_reader: Arc<std::sync::RwLock<HashMap<SourceId, ObservableSourceState<SourceId>>>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> std::io::Result<()> {
    let start_time = Instant::now();
    let timeout = std::time::Duration::from_millis(500);

    let path = match config.observation_path {
        Some(path) => path,
        None => return Ok(()),
    };

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions =
        PermissionsExt::from_mode(config.observation_permissions);

    let observe_listener = create_unix_socket_with_permissions(&path, permissions)?;
    let observe_permits = Arc::new(tokio::sync::Semaphore::new(8));

    loop {
        let permit = observe_permits
            .clone()
            .acquire_owned()
            .await
            .expect("Semaphore for observability was unexpectedly closed");
        let (mut stream, _addr) = match observe_listener.accept().await {
            Ok(a) => a,
            Err(e) if matches!(e.raw_os_error(), Some(ECONNABORTED)) => {
                debug!("Unexpectedly closed unix socket: {e}");
                continue;
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(ENFILE) | Some(EMFILE) | Some(ENOMEM) | Some(ENOBUFS)
                ) =>
            {
                error!(
                    "Not enough resources available to accept incoming observability socket: {e}"
                );
                tokio::time::sleep(timeout).await;
                continue;
            }
            Err(e) => {
                error!("Could not accept connection due to unexpected problem: {e}");
                return Err(e);
            }
        };
        let sources_reader = sources_reader.clone();
        let server_reader = server_reader.clone();
        let system_reader = system_reader.clone();

        let fut = async move {
            handle_connection(
                &mut stream,
                start_time,
                &sources_reader,
                server_reader,
                system_reader,
            )
            .await
        };

        tokio::spawn(async move {
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => debug!("Returning observability records timed out"),
                Ok(Err(err)) => warn!("error handling connection: {err}"),
                Ok(_) => trace!("Returned observability records to connection"),
            }
            drop(permit);
        });
    }
}

async fn handle_connection(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    start_time: Instant,
    sources_reader: &std::sync::RwLock<HashMap<SourceId, ObservableSourceState<SourceId>>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> std::io::Result<()> {
    let observe = ObservableState {
        program: ProgramData::with_uptime(start_time.elapsed().as_secs_f64()),
        sources: sources_reader
            .read()
            .expect("Unexpected poisoned mutex")
            .values()
            .cloned()
            .collect(),
        system: *system_reader.borrow(),
        servers: server_reader.borrow().iter().map(|s| s.into()).collect(),
    };

    super::sockets::write_json(stream, &observe).await?;

    Ok(())
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

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
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

        let mut source_snapshots = HashMap::new();
        let id = SourceId::new();
        source_snapshots.insert(
            id,
            ObservableSourceState {
                timedata: Default::default(),
                unanswered_polls: Reach::default().unanswered_polls(),
                poll_interval: PollIntervalLimits::default().min,
                name: "127.0.0.3:123".into(),
                address: "127.0.0.3:123".into(),
                id,
            },
        );

        let source_snapshots = Arc::new(std::sync::RwLock::new(source_snapshots));

        let (_, servers_reader) = tokio::sync::watch::channel(vec![]);

        let (_, system_reader) = tokio::sync::watch::channel(SystemSnapshot {
            stratum: 1,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot {
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
            observer(config, source_snapshots, servers_reader, system_reader)
                .await
                .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();
        let mut buf = vec![];
        let result: ObservableState = crate::daemon::sockets::read_json(&mut reader, &mut buf)
            .await
            .unwrap();

        // Deal with randomized order
        assert_eq!(result.sources.len(), 1);

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

        let mut source_snapshots = HashMap::new();
        let id = SourceId::new();
        source_snapshots.insert(
            id,
            ObservableSourceState {
                timedata: Default::default(),
                unanswered_polls: Reach::default().unanswered_polls(),
                poll_interval: PollIntervalLimits::default().min,
                name: "127.0.0.3:123".into(),
                address: "127.0.0.3:123".into(),
                id,
            },
        );

        let source_snapshots = Arc::new(std::sync::RwLock::new(source_snapshots));
        let source_snapshots_clone = source_snapshots.clone();

        let (mut server_writer, servers_reader) = tokio::sync::watch::channel(vec![]);

        let (mut system_writer, system_reader) = tokio::sync::watch::channel(SystemSnapshot {
            stratum: 1,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot {
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
            observer(config, source_snapshots, servers_reader, system_reader)
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
        let _ = source_snapshots_clone
            .write()
            .expect("Unexpected poisoned mutex")
            .len();
        let _ = server_writer.borrow_mut();

        handle.abort();
    }
}
