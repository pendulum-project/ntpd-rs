use crate::{
    config::PeerConfig,
    peer::{MsgForSystem, PeerChannels, PeerTask, ResetEpoch},
    peer_manager::{PeerIndex, Peers},
};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    ClockController, ClockUpdateResult, FilterAndCombine, NtpClock, NtpInstant, PeerSnapshot,
    PollInterval, SystemConfig, SystemSnapshot,
};
use tracing::info;

use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Spawn the NTP daemon
pub async fn spawn(
    config: Arc<tokio::sync::RwLock<SystemConfig>>,
    peer_configs: &[PeerConfig],
    peers_rwlock: Arc<tokio::sync::RwLock<Peers>>,
    system_rwlock: Arc<tokio::sync::RwLock<SystemSnapshot>>,
) -> std::io::Result<()> {
    // send the reset signal to all peers
    let reset_epoch: ResetEpoch = ResetEpoch::default();
    let (reset_tx, reset_rx) = watch::channel::<ResetEpoch>(reset_epoch);

    // receive peer snapshots from all peers
    let (msg_for_system_tx, msg_for_system_rx) = mpsc::channel::<MsgForSystem>(32);

    for (index, peer_config) in peer_configs.iter().enumerate() {
        let channels = PeerChannels {
            msg_for_system_sender: msg_for_system_tx.clone(),
            system_snapshots: system_rwlock.clone(),
            reset: reset_rx.clone(),
            system_config: config.clone(),
        };

        PeerTask::spawn(
            PeerIndex { index },
            &peer_config.addr,
            UnixNtpClock::new(),
            channels,
        )
        .await?;
    }

    let peers = Peers::new(peer_configs);

    {
        let mut writer = peers_rwlock.write().await;
        *writer = peers;
    }

    let mut system = System {
        config,
        global_system_snapshot: system_rwlock,
        peers_rwlock,

        msg_for_system_rx,
        reset_tx,

        reset_epoch,
        controller: ClockController::new(UnixNtpClock::new()),
    };

    system.run().await
}

struct System<C: NtpClock> {
    config: Arc<tokio::sync::RwLock<SystemConfig>>,
    global_system_snapshot: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    peers_rwlock: Arc<tokio::sync::RwLock<Peers>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    reset_tx: watch::Sender<ResetEpoch>,

    reset_epoch: ResetEpoch,
    controller: ClockController<C>,
}

impl<C: NtpClock> System<C> {
    async fn run(&mut self) -> std::io::Result<()> {
        let mut snapshots = Vec::with_capacity(self.peers_rwlock.read().await.size());

        while let Some(msg_for_system) = self.msg_for_system_rx.recv().await {
            let ntp_instant = NtpInstant::now();
            let system_poll = self.global_system_snapshot.read().await.poll_interval;

            // ensure the config is not updated in the middle of clock selection
            let config = *self.config.read().await;

            self.peers_rwlock
                .write()
                .await
                .update(msg_for_system, self.reset_epoch);

            if requires_clock_recalculation(
                msg_for_system,
                self.reset_epoch,
                ntp_instant,
                config,
                system_poll,
            ) {
                self.recalculate_clock(&mut snapshots, config, ntp_instant, system_poll)
                    .await;
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }

    async fn recalculate_clock(
        &mut self,
        snapshots: &mut Vec<PeerSnapshot>,
        config: SystemConfig,
        ntp_instant: NtpInstant,
        system_poll: PollInterval,
    ) {
        snapshots.clear();
        snapshots.extend(self.peers_rwlock.read().await.valid_snapshots());
        let result = FilterAndCombine::run(&config, &*snapshots, ntp_instant, system_poll);
        let clock_select = match result {
            Some(clock_select) => clock_select,
            None => {
                info!("filter and combine did not produce a result");
                return;
            }
        };
        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
        info!(offset_ms, jitter_ms, "system offset and jitter");
        let adjust_type = self.controller.update(
            &config,
            clock_select.system_offset,
            clock_select.system_jitter,
            clock_select.system_root_delay,
            clock_select.system_root_dispersion,
            clock_select.system_peer_snapshot.leap_indicator,
            clock_select.system_peer_snapshot.time,
        );
        match adjust_type {
            ClockUpdateResult::Panic => {
                panic!(
                    r"Unusually large clock step suggested,
                                please manually verify system clock and reference clock
                                     state and restart if appropriate."
                )
            }
            ClockUpdateResult::Step => {
                self.reset_peers().await;
            }
            _ => {}
        }
        if adjust_type != ClockUpdateResult::Ignore {
            let mut global = self.global_system_snapshot.write().await;
            global.poll_interval = self.controller.preferred_poll_interval();
            global.leap_indicator = clock_select.system_peer_snapshot.leap_indicator;
        }
    }

    async fn reset_peers(&mut self) {
        self.peers_rwlock.write().await.reset_all();
        self.reset_epoch = self.reset_epoch.inc();
        self.reset_tx.send_replace(self.reset_epoch);
    }
}

fn requires_clock_recalculation(
    msg: MsgForSystem,
    current_reset_epoch: ResetEpoch,

    local_clock_time: NtpInstant,
    config: SystemConfig,
    system_poll: PollInterval,
) -> bool {
    if let MsgForSystem::NewMeasurement(_, msg_reset_epoch, snapshot) = msg {
        msg_reset_epoch == current_reset_epoch
            && snapshot
                .accept_synchronization(
                    local_clock_time,
                    config.frequency_tolerance,
                    config.distance_threshold,
                    system_poll,
                )
                .is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::{peer_snapshot, NtpDuration, NtpLeapIndicator, NtpTimestamp, PeerStatistics};

    use crate::config::PeerHostMode;

    use crate::config::PeerHostMode;

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

    #[test]
    fn test_requires_clock_recalculation() {
        let base = NtpInstant::now();
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();

        let config = SystemConfig::default();

        assert_eq!(
            requires_clock_recalculation(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    prev_epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
                base,
                config,
                PollInterval::MIN,
            ),
            false
        );

        assert_eq!(
            requires_clock_recalculation(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(1.0),
                        NtpDuration::from_seconds(2.0),
                    ),
                ),
                epoch,
                base,
                config,
                PollInterval::MIN,
            ),
            false
        );

        assert_eq!(
            requires_clock_recalculation(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
                base,
                config,
                PollInterval::MIN,
            ),
            true
        );

        assert_eq!(
            requires_clock_recalculation(
                MsgForSystem::UpdatedSnapshot(
                    PeerIndex { index: 1 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
                base,
                config,
                PollInterval::MIN,
            ),
            false
        );

        assert_eq!(
            requires_clock_recalculation(
                MsgForSystem::MustDemobilize(PeerIndex { index: 1 }),
                epoch,
                base,
                config,
                PollInterval::MIN,
            ),
            false
        );
    }

    fn test_peer_configs(n: usize) -> Vec<PeerConfig> {
        (0..n)
            .map(|i| PeerConfig {
                addr: format!("127.0.0.{i}:123"),
                mode: PeerHostMode::Server,
            })
            .collect()
    }

    #[tokio::test]
    async fn test_system_reset() {
        let config = Arc::new(tokio::sync::RwLock::new(SystemConfig::default()));
        config.write().await.min_intersection_survivors = 1;
        let reset_epoch = ResetEpoch::default();
        let (reset_tx, mut reset_rx) = watch::channel::<ResetEpoch>(reset_epoch);
        let (msg_for_system_tx, msg_for_system_rx) = mpsc::channel::<MsgForSystem>(32);
        let global_system_snapshot = Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default()));

        let peers_rwlock = Arc::new(tokio::sync::RwLock::new(Peers::new(&test_peer_configs(4))));
        let peers_copy = peers_rwlock.clone();

        let handle = tokio::spawn(async move {
            let mut system = System {
                config,
                global_system_snapshot,
                peers_rwlock,

                msg_for_system_rx,
                reset_tx,

                reset_epoch,
                controller: ClockController::new(TestClock {}),
            };

            system.run().await
        });

        let prev_epoch = *reset_rx.borrow_and_update();

        msg_for_system_tx
            .send(MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                prev_epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(200.0),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    NtpInstant::now(),
                    NtpDuration::from_seconds(0.1),
                    NtpDuration::from_seconds(0.05),
                ),
            ))
            .await
            .unwrap();

        reset_rx.changed().await.unwrap();

        assert_ne!(*reset_rx.borrow(), prev_epoch);
        assert_eq!(peers_copy.read().await.valid_snapshots().count(), 0);

        msg_for_system_tx
            .send(MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                prev_epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(200.0),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    NtpInstant::now(),
                    NtpDuration::from_seconds(0.1),
                    NtpDuration::from_seconds(0.05),
                ),
            ))
            .await
            .unwrap();

        // Note: this is not a 100% reliable for ensuring system has handled previous message
        // but should work often enough that we should see any problem.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(peers_copy.read().await.valid_snapshots().count(), 0);

        handle.abort();
    }
}
