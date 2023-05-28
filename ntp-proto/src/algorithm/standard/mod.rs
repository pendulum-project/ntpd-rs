mod clock_controller;
mod clock_select;
mod config;
mod filter;
mod peer;

#[cfg(feature = "fuzz")]
pub use clock_select::fuzz_find_interval;

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use tracing::{error, info};

use clock_controller::{ClockController, ClockUpdateResult};
use clock_select::FilterAndCombine;
use filter::LastMeasurements;
use peer::{PeerTimeSnapshot, PeerTimeState};

use crate::{
    exitcode, Measurement, NtpClock, NtpDuration, NtpInstant, ObservablePeerTimedata, SystemConfig,
    TimeSnapshot,
};

use self::config::AlgorithmConfig;

use super::{StateUpdate, TimeSyncController};

#[derive(Debug)]
pub struct StandardClockController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> {
    clock: C,
    controller: ClockController<C>,
    peerstate: HashMap<PeerID, ControllerPeerState>,
    timestate: TimeSnapshot,
    config: SystemConfig,
    algo_config: AlgorithmConfig,
    last_reset: Option<NtpInstant>,
}

#[derive(Debug, Clone)]
struct ControllerPeerState {
    timestate: PeerTimeState,
    usable: bool,
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> StandardClockController<C, PeerID> {
    fn run_peer_update(&mut self, now: NtpInstant, id: PeerID, measurement: Measurement) -> bool {
        let current_peerstate = match self.peerstate.get_mut(&id) {
            Some(v) => v,
            None => return false,
        };
        let update_result =
            current_peerstate
                .timestate
                .update(measurement, self.timestate, &self.algo_config);
        update_result.is_none()
            || !current_peerstate.usable
            || PeerTimeSnapshot::from_timestate(&current_peerstate.timestate)
                .accept_synchronization(
                    now,
                    self.algo_config.frequency_tolerance,
                    self.algo_config.distance_threshold,
                    self.timestate.poll_interval,
                )
                .is_err()
    }

    fn recalculate_clock(&mut self, now: NtpInstant) -> StateUpdate<PeerID> {
        let snapshots: Vec<_> = self
            .peerstate
            .iter()
            .filter_map(|(index, state)| match state.usable {
                true => Some((*index, PeerTimeSnapshot::from_timestate(&state.timestate))),
                false => None,
            })
            .collect();
        let result = FilterAndCombine::run(
            &self.config,
            &self.algo_config,
            &snapshots,
            now,
            self.timestate.poll_interval,
        );
        let clock_select = match result {
            Some(clock_select) => clock_select,
            None => {
                if self.controller.is_startup() {
                    info!("ntpd-rs is still starting up (collecting initial samples)");
                } else if self.controller.is_measuring_frequency() {
                    let minutes = self.algo_config.frequency_measurement_period.to_seconds() / 60.0;
                    info!("ntpd-rs is still in the frequency measurement period (configured as {minutes:.2} min)");
                } else {
                    info!("filter and combine did not produce a result");
                }
                return StateUpdate::default();
            }
        };
        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
        info!("Measured offset: {}±{}ms", offset_ms, jitter_ms);

        let adjust_type = self.controller.update(
            &self.config,
            &self.algo_config,
            &self.timestate,
            clock_select.system_offset,
            clock_select.system_root_delay,
            clock_select.system_root_dispersion,
            clock_select.system_peer_snapshot.1.leap_indicator,
            clock_select.system_peer_snapshot.1.time,
        );
        let offset_ms = self.controller.offset().to_seconds() * 1000.0;
        let jitter_ms = self.controller.jitter().to_seconds() * 1000.0;
        info!("Estimated offset: {}±{}ms", offset_ms, jitter_ms);

        match adjust_type {
            ClockUpdateResult::Panic => {
                error!("Unusually large clock step suggested, please manually verify system clock and reference clock state and restart if appropriate.");
                std::process::exit(exitcode::SOFTWARE);
            }
            ClockUpdateResult::Step => {
                for (_, peerstate) in self.peerstate.iter_mut() {
                    peerstate.timestate.reset_measurements();
                }
                self.last_reset = Some(now);
            }
            _ => {}
        }
        if adjust_type != ClockUpdateResult::Ignore {
            self.timestate.poll_interval = self.controller.preferred_poll_interval();
            self.timestate.leap_indicator = clock_select.system_peer_snapshot.1.leap_indicator;
            self.timestate.accumulated_steps = self.controller.accumulated_steps();
            self.timestate.root_delay = clock_select.system_root_delay;
            self.timestate.root_dispersion = clock_select.system_root_dispersion;

            StateUpdate {
                used_peers: Some(vec![clock_select.system_peer_snapshot.0]),
                time_snapshot: Some(self.timestate),
                next_update: None,
            }
        } else {
            StateUpdate::default()
        }
    }
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> TimeSyncController<C, PeerID>
    for StandardClockController<C, PeerID>
{
    type AlgorithmConfig = AlgorithmConfig;

    fn new(clock: C, config: SystemConfig, algo_config: AlgorithmConfig) -> Self {
        let timestate = TimeSnapshot::default();
        Self {
            clock: clock.clone(),
            controller: ClockController::new(clock, &timestate, &config),
            peerstate: HashMap::new(),
            timestate,
            config,
            algo_config,
            last_reset: None,
        }
    }

    fn update_config(&mut self, config: SystemConfig, algo_config: AlgorithmConfig) {
        self.config = config;
        self.algo_config = algo_config;
    }

    fn peer_add(&mut self, id: PeerID) {
        let time = NtpInstant::now();
        self.peerstate.insert(
            id,
            ControllerPeerState {
                timestate: PeerTimeState {
                    statistics: Default::default(),
                    last_measurements: LastMeasurements::new(time),
                    time,
                },
                usable: false,
            },
        );
    }

    fn peer_remove(&mut self, id: PeerID) {
        self.peerstate.remove(&id);
    }

    fn peer_update(&mut self, id: PeerID, usable: bool) {
        if let Some(state) = self.peerstate.get_mut(&id) {
            state.usable = usable;
        }
    }

    fn peer_measurement(
        &mut self,
        id: PeerID,
        measurement: crate::peer::Measurement,
    ) -> StateUpdate<PeerID> {
        let now = NtpInstant::now();

        // Ignore measurements within a second of the last reset
        if let Some(reset) = self.last_reset {
            if now.abs_diff(reset) < NtpDuration::ONE {
                return StateUpdate::default();
            }
        }

        // Update peer's state and check if the clock needs recalculation
        if !self.run_peer_update(now, id, measurement) {
            return StateUpdate::default();
        }

        self.recalculate_clock(now)
    }

    fn time_update(&mut self) -> StateUpdate<PeerID> {
        // Not needed for standard algorithm
        StateUpdate::default()
    }

    fn peer_snapshot(&self, id: PeerID) -> Option<ObservablePeerTimedata> {
        self.peerstate
            .get(&id)
            .map(|state| PeerTimeSnapshot::from_timestate(&state.timestate))
            .map(|snapshot| ObservablePeerTimedata {
                offset: snapshot.statistics.offset,
                uncertainty: snapshot.statistics.dispersion
                    + NtpDuration::from_seconds(snapshot.statistics.jitter),
                delay: snapshot.statistics.delay,
                remote_delay: snapshot.root_delay,
                remote_uncertainty: snapshot.root_dispersion,
                last_update: self.clock.now().expect("Unable to get current time")
                    + NtpDuration::from_system_duration(snapshot.time.elapsed()),
            })
    }
}
