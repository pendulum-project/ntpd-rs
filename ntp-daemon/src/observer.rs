use crate::server::ServerStats;
use crate::{sockets::create_unix_socket, system::ServerData};
use ntp_proto::{ObservablePeerTimedata, PollInterval, Reach, ReferenceId, SystemSnapshot};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use tokio::task::JoinHandle;
use tracing::warn;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub system: SystemSnapshot,
    pub peers: Vec<ObservablePeerState>,
    pub servers: Vec<ObservableServerState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableServerState {
    pub address: SocketAddr,
    pub stats: ServerStats,
}

impl From<&ServerData> for ObservableServerState {
    fn from(data: &ServerData) -> Self {
        ObservableServerState {
            address: data.config.addr,
            stats: data.stats.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ObservablePeerState {
    Nothing,
    Observable {
        #[serde(flatten)]
        timedata: ObservablePeerTimedata,
        reachability: Reach,
        poll_interval: PollInterval,
        peer_id: ReferenceId,
        address: String,
    },
}

pub async fn spawn(
    config: &crate::config::ObserveConfig,
    peers_reader: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
) -> JoinHandle<std::io::Result<()>> {
    let config = config.clone();
    tokio::spawn(async move {
        let result = observer(config, peers_reader, server_reader, system_reader).await;
        if let Err(ref e) = result {
            warn!("Abnormal termination of the state observer: {}", e);
            warn!("The state observer will not be available");
        }
        result
    })
}

async fn observer(
    config: crate::config::ObserveConfig,
    peers_reader: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    server_reader: tokio::sync::watch::Receiver<Vec<ServerData>>,
    system_reader: tokio::sync::watch::Receiver<SystemSnapshot>,
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
            peers: peers_reader.borrow().to_owned(),
            system: *system_reader.borrow(),
            servers: server_reader.borrow().iter().map(|s| s.into()).collect(),
        };

        crate::sockets::write_json(&mut stream, &observe).await?;
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::BorrowMut, time::Duration};

    use ntp_proto::{
        NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, PollInterval, PollIntervalLimits,
        Reach, ReferenceId, TimeSnapshot,
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

        fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn ntp_algorithm_update(
            &self,
            _offset: NtpDuration,
            _poll_interval: PollInterval,
        ) -> Result<(), Self::Error> {
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
        let config = crate::config::ObserveConfig {
            path: Some(path.clone()),
            mode: 0o700,
        };

        let (_, peers_reader) = tokio::sync::watch::channel(vec![
            ObservablePeerState::Nothing,
            ObservablePeerState::Nothing,
            ObservablePeerState::Observable {
                timedata: Default::default(),
                reachability: Reach::default(),
                poll_interval: PollIntervalLimits::default().min,
                peer_id: ReferenceId::from_ip("127.0.0.1".parse().unwrap()),
                address: "127.0.0.3:123".into(),
            },
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

        let (mut peers_writer, peers_reader) = tokio::sync::watch::channel(vec![
            ObservablePeerState::Nothing,
            ObservablePeerState::Nothing,
            ObservablePeerState::Observable {
                timedata: Default::default(),
                reachability: Reach::default(),
                poll_interval: PollIntervalLimits::default().min,
                peer_id: ReferenceId::from_ip("127.0.0.1".parse().unwrap()),
                address: "127.0.0.3:123".into(),
            },
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
