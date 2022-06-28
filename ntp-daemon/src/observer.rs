use crate::{ObservablePeerState, Peers};
use ntp_proto::SystemSnapshot;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tracing::error;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub system: SystemSnapshot,
    pub peers: Vec<ObservablePeerState>,
}

pub async fn spawn(
    config: &crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers>>,
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

async fn observer(
    config: crate::config::ObserveConfig,
    peers_reader: Arc<tokio::sync::RwLock<Peers>>,
    system_reader: Arc<tokio::sync::RwLock<SystemSnapshot>>,
) -> std::io::Result<()> {
    let path = match config.path {
        Some(path) => path,
        None => return Ok(()),
    };

    // must unlink path before the bind below (otherwise we get "address already in use")
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let peers_listener = UnixListener::bind(&path)?;

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
        NtpDuration, NtpInstant, NtpLeapIndicator, PeerSnapshot, PeerStatistics, PollInterval,
        Reach, ReferenceId,
    };
    use tokio::{io::AsyncReadExt, net::UnixStream};

    use crate::system::PeerStatus;

    use super::*;

    #[tokio::test]
    async fn test_observation() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-2");
        let config = crate::config::ObserveConfig {
            path: Some(path.clone()),
            mode: 0o700,
        };

        let peers_reader = Arc::new(tokio::sync::RwLock::new(Peers::from_statuslist(&[
            PeerStatus::Demobilized,
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
        ])));

        let system_reader = Arc::new(tokio::sync::RwLock::new(SystemSnapshot {
            poll_interval: PollInterval::MIN,
            precision: NtpDuration::from_seconds(1e-3),
            leap_indicator: NtpLeapIndicator::Leap59,
        }));

        let handle = tokio::spawn(async move {
            observer(config, peers_reader, system_reader).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut reader = UnixStream::connect(path).await.unwrap();

        let mut buf = vec![];
        while reader.read_buf(&mut buf).await.unwrap() != 0 {}
        let result: ObservableState = serde_json::from_slice(&buf).unwrap();

        assert!(matches!(result.peers[0], ObservablePeerState::Nothing));
        assert!(matches!(result.peers[1], ObservablePeerState::Nothing));
        assert!(matches!(
            result.peers[2],
            ObservablePeerState::Observable { .. }
        ));

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

        let peers_reader = Arc::new(tokio::sync::RwLock::new(Peers::from_statuslist(&[
            PeerStatus::Demobilized,
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
        ])));

        let peers_writer = peers_reader.clone();

        let system_reader = Arc::new(tokio::sync::RwLock::new(SystemSnapshot {
            poll_interval: PollInterval::MIN,
            precision: NtpDuration::from_seconds(1e-3),
            leap_indicator: NtpLeapIndicator::Leap59,
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
        drop(bufref);

        // Ensure neither lock is held long term
        system_writer.write().await;
        peers_writer.write().await;

        handle.abort();
    }
}
