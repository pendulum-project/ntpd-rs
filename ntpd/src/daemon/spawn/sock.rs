use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ntp_proto::SourceConfig;
use statime_algo::LinkConfig;
use statime_base::{Duration, SourceType, StdController};
use tokio::sync::mpsc;

use crate::daemon::{
    config::SockSourceConfig,
    sock_source::SockSourceTask,
    spawn::{CreationParameters, LinkTerminationReason},
};

use super::{ClockId, Spawner, SpawnerId};

#[derive(Debug, Clone, PartialEq)]
pub struct SockSpawnerConfig {
    pub path: PathBuf,
    pub precision: Duration,
    pub accuracy: Duration,
}

pub struct SockSpawner {
    config: SockSpawnerConfig,
    state: Arc<Mutex<SockSpawnerState>>,
}

#[derive(Default)]
struct SockSpawnerState {
    has_spawned: bool,
}

impl SockSpawner {
    pub fn new(config: SockSpawnerConfig) -> SockSpawner {
        SockSpawner {
            config,
            state: Arc::default(),
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for SockSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let config = self.config.clone();
        let state = self.state.clone();

        Box::new(async move {
            Ok(CreationParameters {
                stype: SourceType::Sock,
                link_config: LinkConfig {
                    /// Not relevant as sock sources have fixed measurement periods.
                    desired_error_bound: Duration::from_seconds_nanos(0, 1_000),
                    period: None,
                }
                .into(),
                tracked_link_config: None,
                creator: Box::new(
                    move |controller: TimeController::Link<Arc<TimeController>>,
                          clock,
                          managers| {
                        state.lock().unwrap().has_spawned = true;
                        SockSourceTask::spawn(
                            clock,
                            controller,
                            crate::daemon::sock_source::SockSourceConfig {
                                path: config.path,
                                precision: config.precision,
                                accuracy: config.accuracy,
                            },
                        )
                    },
                ),
            })
        })
    }

    fn needs_spawn(&self) -> bool {
        !self.state.lock().unwrap().has_spawned
    }

    fn source_terminated(
        &mut self,
        id: statime_base::LinkId,
        reason: super::LinkTerminationReason,
    ) {
        if reason != LinkTerminationReason::MustDemobilize {
            let mut state = self.state.lock().unwrap();
            state.has_spawned = false;
        }
    }
}
