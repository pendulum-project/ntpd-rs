mod clock_controller;
mod clock_select;
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
    Measurement, NtpClock, NtpDuration, NtpInstant, ObservablePeerTimedata, SystemConfig,
    TimeSnapshot,
};

use super::TimeSyncController;

#[derive(Debug)]
pub struct StandardClockController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> {
    clock: C,
    controller: ClockController<C>,
    peerstate: HashMap<PeerID, ControllerPeerState>,
    timestate: TimeSnapshot,
    config: SystemConfig,
    last_reset: Option<NtpInstant>,
}

#[derive(Debug, Clone)]
struct ControllerPeerState {
    timestate: PeerTimeState,
    usable: bool,
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> StandardClockController<C, PeerID> {
    fn run_peer_update(
        &mut self,
        now: NtpInstant,
        id: PeerID,
        measurement: Measurement,
        packet: crate::NtpPacket<'static>,
    ) -> bool {
        let current_peerstate = match self.peerstate.get_mut(&id) {
            Some(v) => v,
            None => return false,
        };
        let update_result = current_peerstate.timestate.update(
            measurement,
            packet.clone().into_owned(),
            self.timestate,
            &self.config,
        );
        update_result.is_none()
            || !current_peerstate.usable
            || PeerTimeSnapshot::from_timestate(&current_peerstate.timestate)
                .accept_synchronization(
                    now,
                    self.config.frequency_tolerance,
                    self.config.distance_threshold,
                    self.timestate.poll_interval,
                )
                .is_err()
    }

    fn recalculate_clock(&mut self, now: NtpInstant) -> Option<(Vec<PeerID>, TimeSnapshot)> {
        let snapshots: Vec<_> = self
            .peerstate
            .iter()
            .filter_map(|(index, state)| match state.usable {
                true => Some((*index, PeerTimeSnapshot::from_timestate(&state.timestate))),
                false => None,
            })
            .collect();
        let result =
            FilterAndCombine::run(&self.config, &snapshots, now, self.timestate.poll_interval);
        let clock_select = match result {
            Some(clock_select) => clock_select,
            None => {
                info!("filter and combine did not produce a result");
                return None;
            }
        };
        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
        info!(offset_ms, jitter_ms, "Measured offset and jitter");
        let adjust_type = self.controller.update(
            &self.config,
            &self.timestate,
            clock_select.system_offset,
            clock_select.system_root_delay,
            clock_select.system_root_dispersion,
            clock_select.system_peer_snapshot.1.leap_indicator,
            clock_select.system_peer_snapshot.1.time,
        );
        let offset_ms = self.controller.offset().to_seconds() * 1000.0;
        let jitter_ms = self.controller.jitter().to_seconds() * 1000.0;
        info!(offset_ms, jitter_ms, "Estimated clock offset and jitter");
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

            Some((vec![clock_select.system_peer_snapshot.0], self.timestate))
        } else {
            None
        }
    }
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> TimeSyncController<C, PeerID>
    for StandardClockController<C, PeerID>
{
    fn new(clock: C, config: SystemConfig) -> Self {
        let timestate = TimeSnapshot::default();
        Self {
            clock: clock.clone(),
            controller: ClockController::new(clock, &timestate, &config),
            peerstate: HashMap::new(),
            timestate,
            config,
            last_reset: None,
        }
    }

    fn update_config(&mut self, config: SystemConfig) {
        self.config = config;
    }

    fn peer_add(&mut self, id: PeerID) {
        let time = NtpInstant::now();
        self.peerstate.insert(
            id,
            ControllerPeerState {
                timestate: PeerTimeState {
                    statistics: Default::default(),
                    last_measurements: LastMeasurements::new(time),
                    last_packet: Default::default(),
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
        packet: crate::NtpPacket<'static>,
    ) -> Option<(Vec<PeerID>, TimeSnapshot)> {
        let now = NtpInstant::now();

        // Ignore measurements within a second of the last reset
        if let Some(reset) = self.last_reset {
            if now.abs_diff(reset) < NtpDuration::ONE {
                return None;
            }
        }

        // Update peer's state and check if the clock needs recalculation
        if !self.run_peer_update(now, id, measurement, packet) {
            return None;
        }

        self.recalculate_clock(now)
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
