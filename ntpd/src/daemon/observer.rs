use crate::daemon::config::ObservabilityConfig;
use crate::daemon::spawn::{Spawner, SpawnerId};
use crate::daemon::system::System;

use super::server::ServerStats;
use super::sockets::create_unix_socket_with_permissions;
use libc::{ECONNABORTED, EMFILE, ENFILE, ENOBUFS, ENOMEM};
use ntp_proto::{ClockId, ObservableSourceState, SystemSnapshot};
use statime_base::{Clock, LinkId, StdController, TAI, Timestamp};
use std::collections::HashMap;
use std::convert::Into;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, time::Instant};
use tokio::task::JoinHandle;
use tracing::{Instrument, Span, debug, error, instrument, trace, warn};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableState {
    pub program: ProgramData,
    pub system: SystemSnapshot,
    pub sources: Vec<ObservableSourceState>,
    pub servers: Vec<ObservableServerState>,
    pub spawners: Vec<ObservableSpawnerState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramData {
    pub version: String,
    pub build_commit: String,
    pub build_commit_date: String,
    pub uptime_seconds: f64,
    pub now: Timestamp<TAI>,
}

impl ProgramData {
    pub fn with_dynamics(uptime_seconds: f64, now: Timestamp<TAI>) -> ProgramData {
        ProgramData {
            uptime_seconds,
            now,
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
            now: Timestamp::from_seconds_nanos_since_unix_epoch(0, 0),
        }
    }
}

///FIXME: Remove when the new system is in place and observability is being build up
#[derive(Debug, Clone, Copy)]
pub struct ServerData {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableServerState {
    pub address: SocketAddr,
    pub stats: ServerStats,
}

impl From<&ServerData> for ObservableServerState {
    fn from(data: &ServerData) -> Self {
        ObservableServerState {
            address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 123),
            stats: ServerStats::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableSpawnerState {
    pub id: SpawnerId,
    pub spawn_state: String,
    pub current_timeout: Duration,
    pub last_spawn: Duration,
    pub driven_links: Vec<ObservableDrivenLink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObservableDrivenLink {
    pub link_id: LinkId,
    pub source_type: String,
}

#[instrument(level = tracing::Level::ERROR, skip_all, name = "Observer", fields(path = debug(config.observation_path.clone())))]
pub fn spawn<
    C: 'static + Clock<TAI> + Send,
    TimeController: StdController + Send + Sync + 'static,
>(
    config: ObservabilityConfig,
    system: Arc<System<TimeController>>,
    clock: C,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(
        (async move {
            let result = observer(config, system, clock).await;
            if let Err(ref e) = result {
                warn!("Abnormal termination of the state observer: {e}");
                warn!("The state observer will not be available");
            }
            result
        })
        .instrument(Span::current()),
    )
}

async fn observer<C: 'static + Clock<TAI> + Send, TimeController: StdController + Send + Sync>(
    config: ObservabilityConfig,
    system: Arc<System<TimeController>>,
    clock: C,
) -> std::io::Result<()> where
{
    let start_time = Instant::now();
    let timeout = std::time::Duration::from_millis(500);

    let Some(path) = config.observation_path else {
        return Ok(());
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
            Err(e) if matches!(e.raw_os_error(), Some(ENFILE | EMFILE | ENOMEM | ENOBUFS)) => {
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

        let spawners = system.spawners();
        let now = clock.now().expect("Unable to get current time");
        let fut = async move { handle_connection(&mut stream, start_time, spawners, now).await };

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
    spawners: Vec<ObservableSpawnerState>,
    now: Timestamp<TAI>,
) -> std::io::Result<()> {
    let observe = ObservableState {
        program: ProgramData::with_dynamics(start_time.elapsed().as_secs_f64(), now),
        sources: Vec::new(),
        system: SystemSnapshot::default(),
        servers: Vec::new(),
        spawners,
    };
    super::sockets::write_json(stream, &observe).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;
    use std::time::Duration;

    use ntp_proto::v5::BloomFilter;
    use ntp_proto::{NtpSnapshot, PollIntervalLimits, Reach, ReferenceId};
    use statime_base::{LeapStatus, TimeSnapshot, Timestamp};
    use tokio::{io::AsyncReadExt, net::UnixStream};

    use crate::test::alloc_port;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct TestClock;

    impl Clock<TAI> for TestClock {
        fn now(&self) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            Ok(Timestamp::from_seconds_nanos_since_unix_epoch(0, 0))
        }

        fn set_frequency(&self, _freq: f64) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!()
        }

        fn get_frequency(&self) -> Result<f64, statime_base::ClockError> {
            Ok(0.0)
        }

        fn max_frequency(&self) -> Result<f64, statime_base::ClockError> {
            Ok(500e-6)
        }

        fn step_clock(
            &self,
            _offset: statime_base::Duration,
        ) -> Result<Timestamp<TAI>, statime_base::ClockError> {
            unimplemented!()
        }

        fn error_estimate_update(
            &self,
            _est_error: statime_base::Duration,
            _max_error: statime_base::Duration,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }

        fn leap_update(&self, _leap_status: LeapStatus) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }

        fn synchronization_update(
            &self,
            _synchronized: bool,
        ) -> Result<(), statime_base::ClockError> {
            unimplemented!()
        }
    }
}
