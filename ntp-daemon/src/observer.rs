use crate::sockets::create_unix_socket;
use crate::Peers;
use ntp_proto::{NtpClock, PeerStatistics, Reach, ReferenceId, SystemSnapshot};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::error;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub system: SystemSnapshot,
    pub peers: Vec<ObservablePeerState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ObservablePeerState {
    Nothing,
    Observable {
        statistics: PeerStatistics,
        reachability: Reach,
        uptime: std::time::Duration,
        poll_interval: std::time::Duration,
        peer_id: ReferenceId,
        address: String,
    },
}

pub async fn spawn<C: NtpClock + Sync + Send + 'static>(
    config: &crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers<C>>>,
    system_reader: Arc<tokio::sync::RwLock<SystemSnapshot>>,
) -> JoinHandle<std::io::Result<()>> {
    let config = config.clone();
    tokio::spawn(async move {
        let result = observer(config, peers_reader, system_reader).await;
        if let Err(ref e) = result {
            error!("Abnormal termination of state observer: {}", e);
        }
        result
    })
}

async fn observer<C: NtpClock>(
    config: crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers<C>>>,
    system_reader: Arc<tokio::sync::RwLock<SystemSnapshot>>,
) -> std::io::Result<()> {
    let path = match config.path {
        Some(path) => path,
        None => return Ok(()),
    };

    let peers_listener = create_unix_socket(&path)?;

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
    std::fs::set_permissions(&path, permissions)?;

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let observe = ObservableState {
            peers: peers_reader.read().await.observe().collect(),
            system: *system_reader.read().await,
        };

        crate::sockets::write_json(&mut stream, &observe).await?;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntp_proto::{
        NtpDuration, NtpInstant, NtpLeapIndicator, NtpTimestamp, PeerSnapshot, PeerStatistics,
        PollInterval, Reach, ReferenceId,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream};

    use crate::{
        config::{NormalizedAddress, PeerConfig, StandardPeerConfig},
        peer_manager::PeerStatus,
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn set_freq(&self, _freq: f64) -> Result<(), Self::Error> {
            Ok(())
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_clock(
            &self,
            _offset: NtpDuration,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
            _poll_interval: PollInterval,
            _leap_status: NtpLeapIndicator,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_observation() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-2");
        let config = crate::config::ObserveConfig {
            path: Some(path.clone()),
            mode: 0o700,
        };

        let status_list = [
            PeerStatus::NoMeasurement,
            PeerStatus::NoMeasurement,
            PeerStatus::Measurement(PeerSnapshot {
                root_distance_without_time: NtpDuration::from_seconds(0.2),
                statistics: PeerStatistics {
                    offset: NtpDuration::from_seconds(0.05),
                    delay: NtpDuration::from_seconds(0.03),
                    dispersion: NtpDuration::from_seconds(0.05),
                    jitter: 0.2,
                },
                time: NtpInstant::now(),
                stratum: 2,
                peer_id: ReferenceId::from_ip("127.0.0.1".parse().unwrap()),
                poll_interval: PollInterval::MAX,
                reference_id: ReferenceId::from_ip("127.0.0.3".parse().unwrap()),
                our_id: ReferenceId::from_ip("127.0.0.2".parse().unwrap()),
                reach: Reach::default(),
                leap_indicator: NtpLeapIndicator::NoWarning,
                root_delay: NtpDuration::from_seconds(0.2),
                root_dispersion: NtpDuration::from_seconds(0.02),
            }),
        ];

        let peer_configs = [
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.1:123"),
            }),
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.2:123"),
            }),
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.3:123"),
            }),
        ];

        let peers_reader = Arc::new(tokio::sync::RwLock::new(Peers::from_statuslist(
            &status_list,
            &peer_configs,
            TestClock {},
        )));

        let system_reader = Arc::new(tokio::sync::RwLock::new(SystemSnapshot {
            poll_interval: PollInterval::MIN,
            stratum: 1,
            precision: NtpDuration::from_seconds(1e-3),
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            reference_id: ReferenceId::NONE,
            leap_indicator: NtpLeapIndicator::Leap59,
            accumulated_steps: NtpDuration::ZERO,
            accumulated_steps_threshold: None,
        }));

        let handle = tokio::spawn(async move {
            observer(config, peers_reader, system_reader).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();

        let mut buf = vec![];
        while reader.read_buf(&mut buf).await.unwrap() != 0 {}
        let result: ObservableState = serde_json::from_slice(&buf).unwrap();

        // Deal with randomized order
        let mut count = 0;
        for peer in &result.peers {
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
        let config = crate::config::ObserveConfig {
            path: Some(path.clone()),
            mode: 0o700,
        };

        let status_list = [
            PeerStatus::NoMeasurement,
            PeerStatus::NoMeasurement,
            PeerStatus::Measurement(PeerSnapshot {
                root_distance_without_time: NtpDuration::from_seconds(0.2),
                statistics: PeerStatistics {
                    offset: NtpDuration::from_seconds(0.05),
                    delay: NtpDuration::from_seconds(0.03),
                    dispersion: NtpDuration::from_seconds(0.05),
                    jitter: 0.2,
                },
                time: NtpInstant::now(),
                stratum: 2,
                peer_id: ReferenceId::from_ip("127.0.0.1".parse().unwrap()),
                poll_interval: PollInterval::MAX,
                reference_id: ReferenceId::from_ip("127.0.0.3".parse().unwrap()),
                our_id: ReferenceId::from_ip("127.0.0.2".parse().unwrap()),
                reach: Reach::default(),
                leap_indicator: NtpLeapIndicator::NoWarning,
                root_delay: NtpDuration::from_seconds(0.2),
                root_dispersion: NtpDuration::from_seconds(0.02),
            }),
        ];

        let peer_configs = [
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.1:123"),
            }),
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.2:123"),
            }),
            PeerConfig::Standard(StandardPeerConfig {
                addr: NormalizedAddress::new_unchecked("127.0.0.3:123"),
            }),
        ];

        let peers_reader = Arc::new(tokio::sync::RwLock::new(Peers::from_statuslist(
            &status_list,
            &peer_configs,
            TestClock {},
        )));

        let peers_writer = peers_reader.clone();

        let system_reader = Arc::new(tokio::sync::RwLock::new(SystemSnapshot {
            poll_interval: PollInterval::MIN,
            stratum: 1,
            precision: NtpDuration::from_seconds(1e-3),
            reference_id: ReferenceId::NONE,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap_indicator: NtpLeapIndicator::Leap59,
            accumulated_steps: NtpDuration::ZERO,
            accumulated_steps_threshold: None,
        }));

        let system_writer = system_reader.clone();

        let handle = tokio::spawn(async move {
            observer(config, peers_reader, system_reader).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();

        // We do a small partial read of the data to test that whatever
        // happens, the observer doesnt keep a lock alive on either of
        // of the RwLocks.
        let mut buf = [0_u8; 12];
        let mut bufref: &mut [u8] = &mut buf;
        reader.read_buf(&mut bufref).await.unwrap();

        // Ensure neither lock is held long term
        let _ = system_writer.write().await;
        let _ = peers_writer.write().await;

        handle.abort();
    }
}
