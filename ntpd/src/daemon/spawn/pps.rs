use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ntp_proto::SourceConfig;
use statime_algo::LinkConfig;
use statime_base::{Duration, SourceType, StdController};
use tokio::sync::mpsc;

use crate::daemon::{
    config::PpsSourceConfig,
    pps_source::{self, PpsSourceTask},
    spawn::{CreationParameters, LinkTerminationReason},
};

use super::{ClockId, Spawner, SpawnerId};

#[derive(Debug, Clone, PartialEq)]
pub struct PpsSpawnerConfig {
    pub path: PathBuf,
    pub precision: Duration,
    pub accuracy: Duration,
    pub period: Duration,
}

pub struct PpsSpawner {
    config: PpsSpawnerConfig,
    state: Arc<Mutex<PpsSpawnerState>>,
}

#[derive(Default)]
struct PpsSpawnerState {
    has_spawned: bool,
}

impl PpsSpawner {
    pub fn new(config: PpsSpawnerConfig) -> PpsSpawner {
        PpsSpawner {
            config,
            state: Arc::default(),
        }
    }
}

impl<TimeController: StdController> Spawner<TimeController> for PpsSpawner
where
    TimeController::LinkConfig: From<statime_algo::LinkConfig>,
    TimeController::Link<Arc<TimeController>>: Send + 'static,
{
    fn try_spawn(&mut self) -> super::TrySpawnFuture<TimeController> {
        let config = self.config.clone();
        let state = self.state.clone();

        Box::new(async move {
            Ok(CreationParameters {
                stype: SourceType::Ntp,
                link_config: LinkConfig {
                    /// Not relevant as pps sources have fixed measurement periods.
                    desired_error_bound: Duration::from_seconds_nanos(0, 1_000),
                    period: Some(config.period),
                }
                .into(),
                tracked_link_config: None,
                creator: Box::new(
                    move |controller: TimeController::Link<Arc<TimeController>>,
                          clock,
                          managers| {
                        PpsSourceTask::spawn(
                            controller,
                            pps_source::PpsSourceConfig {
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
