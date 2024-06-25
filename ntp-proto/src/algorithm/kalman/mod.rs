use std::{collections::HashMap, fmt::Debug, hash::Hash, time::Duration};

use tracing::{error, info, instrument};

use crate::{
    clock::NtpClock, config::{SourceDefaultsConfig, SynchronizationConfig}, packet::NtpLeapIndicator, source::Measurement, system::TimeSnapshot, time_types::{NtpDuration, NtpTimestamp}
};

use self::{
    combiner::combine,
    config::AlgorithmConfig,
    matrix::{Matrix, Vector},
    source::SourceState,
};

use super::{ObservableSourceTimedata, StateUpdate, TimeSyncController};

mod combiner;
pub(super) mod config;
pub mod matrix;
mod select;
pub mod source;
pub mod combine_with_pps;

fn sqr(x: f64) -> f64 {
    x * x
}

#[derive(Debug, Clone)]
pub struct SourceSnapshot<Index: Copy> {
    index: Index,
    state: Vector<2>,
    uncertainty: Matrix<2, 2>,
    delay: f64,

    source_uncertainty: NtpDuration,
    source_delay: NtpDuration,
    leap_indicator: NtpLeapIndicator,

    last_update: NtpTimestamp,
}

impl<Index: Copy> SourceSnapshot<Index> {
    fn offset(&self) -> f64 {
        self.state.ventry(0)
    }

    fn offset_uncertainty(&self) -> f64 {
        self.uncertainty.entry(0, 0).sqrt()
    }

    fn get_state_vector(&self) -> Vector<2> {
        self.state
    }

    fn get_uncertainty_matrix(&self) -> Matrix<2, 2> {
        self.uncertainty
    }

    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata {
            offset: NtpDuration::from_seconds(self.offset()),
            uncertainty: NtpDuration::from_seconds(self.offset_uncertainty()),
            delay: NtpDuration::from_seconds(self.delay),
            remote_delay: self.source_delay,
            remote_uncertainty: self.source_uncertainty,
            last_update: self.last_update,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KalmanClockController<C: NtpClock, SourceId: Hash + Eq + Copy + Debug> {
    sources: HashMap<SourceId, (SourceState, bool)>,
    clock: C,
    synchronization_config: SynchronizationConfig,
    source_defaults_config: SourceDefaultsConfig,
    algo_config: AlgorithmConfig,
    freq_offset: f64,
    timedata: TimeSnapshot,
    desired_freq: f64,
    in_startup: bool,
    pps_source_id: Option<SourceId>,
}

impl<C: NtpClock, SourceId: Hash + Eq + Copy + Debug> KalmanClockController<C, SourceId> {
    #[instrument(skip(self))]
    fn update_source(&mut self, id: SourceId, measurement: Measurement) -> bool {
        if let Some(_pps_measurement) = &measurement.pps{
            self.pps_source_id = Some(id);
        }
        self.sources.get_mut(&id).map(|state| {
            state.0.update_self_using_measurement(
                &self.source_defaults_config,
                &self.algo_config,
                measurement,
            ) && state.1
        }) == Some(true)
    }

    fn update_clock(&mut self, time: NtpTimestamp) -> StateUpdate<SourceId> {
        //ensure all filters represent the same (current) time
        if self
            .sources
            .iter()
            .filter_map(|(_, (state, _))| state.get_filtertime())
            .any(|sourcetime| time - sourcetime < NtpDuration::ZERO)
        {
            return StateUpdate {
                used_sources: None,
                time_snapshot: Some(self.timedata),
                next_update: None,
            };
        }
        for (_, (state, _)) in self.sources.iter_mut() {
            state.progress_filtertime(time);
        }
        let candidates = if let Some(pps_source) = self.pps_source_id {
            println!("PPS SOURCE INDEX {:?}", pps_source);
        
            // Extract the PPS SourceSnapshot
            let pps_snapshot = self.sources.iter()
                .filter_map(|(index, (state, usable))| {
                    if *index == pps_source && *usable {
                        state.snapshot(*index)
                    } else {
                        None
                    }
                })
                .next();
        
            // Collect the other candidates
            let other_candidates: Vec<_> = self.sources.iter()
                .filter_map(|(index, (state, usable))| {
                    if *usable && *index != pps_source {
                        state.snapshot(*index)
                    } else {
                        None
                    }
                })
                .collect();
        
            // Combine the PPS snapshot with other candidates if PPS snapshot is found
            if let Some(pps_snapshot) = pps_snapshot {
                combine_with_pps::combine_with_pps::<SourceId>(pps_snapshot, other_candidates)
            } else {
                other_candidates
            }
        } else {
            // If pps_source_id is None, just use other_candidates
            self.sources.iter()
                .filter_map(|(index, (state, usable))| {
                    if *usable {
                        state.snapshot(*index)
                    } else {
                        None
                    }
                })
                .collect()
        };

        println!("AFTER COMMBINE WITH PPS: Number of candidates: {}", candidates.len());

        
        let selection = select::select(
            &self.synchronization_config,
            &self.algo_config,
            candidates,
        );
        println!("selection lenght: {}", selection.len());
        if let Some(combined) = combine(&selection, &self.algo_config) {
            info!(
                "Offset: {}+-{}ms, frequency: {}+-{}ppm",
                combined.estimate.ventry(0) * 1e3,
                combined.uncertainty.entry(0, 0).sqrt() * 1e3,
                combined.estimate.ventry(1) * 1e6,
                combined.uncertainty.entry(1, 1).sqrt() * 1e6
            );

            let freq_delta = combined.estimate.ventry(1) - self.desired_freq;
            let freq_uncertainty = combined.uncertainty.entry(1, 1).sqrt();
            let offset_delta = combined.estimate.ventry(0);
            let offset_uncertainty = combined.uncertainty.entry(0, 0).sqrt();
            let next_update = if self.desired_freq == 0.0
                && offset_delta.abs() > offset_uncertainty * self.algo_config.steer_offset_threshold
            {
                // Note: because of threshold effects, offset_delta is likely an extreme estimate
                // at this point. Hence we only correct it partially in order to avoid
                // overcorrecting.
                // The same does not apply to freq_delta, so if we start slewing
                // it can be fully corrected without qualms.
                self.steer_offset(
                    offset_delta
                        - offset_uncertainty
                            * self.algo_config.steer_offset_leftover
                            * offset_delta.signum(),
                    freq_delta,
                )
            } else if freq_delta.abs()
                > freq_uncertainty * self.algo_config.steer_frequency_threshold
            {
                // Note: because of threshold effects, freq_delta is likely an extreme estimate
                // at this point. Hence we only correct it partially in order to avoid
                // overcorrecting.
                self.steer_frequency(
                    freq_delta
                        - freq_uncertainty
                            * self.algo_config.steer_frequency_leftover
                            * freq_delta.signum(),
                );
                None
            } else {
                None
            };

            self.timedata.root_delay = combined.delay;
            self.timedata.root_dispersion =
                NtpDuration::from_seconds(combined.uncertainty.entry(0, 0).sqrt());
            self.clock
                .error_estimate_update(self.timedata.root_dispersion, self.timedata.root_delay)
                .expect("Cannot update clock");

            if let Some(leap) = combined.leap_indicator {
                self.clock.status_update(leap).expect("Cannot update clock");
                self.timedata.leap_indicator = leap;
            }

            // After a succesfull measurement we are out of startup.
            self.in_startup = false;

            StateUpdate {
                used_sources: Some(combined.sources),
                time_snapshot: Some(self.timedata),
                next_update,
            }
        } else {
            info!("No consensus cluster found");
            StateUpdate {
                used_sources: None,
                time_snapshot: Some(self.timedata),
                next_update: None,
            }
        }
    }

    fn check_offset_steer(&mut self, change: f64) {
        let change = NtpDuration::from_seconds(change);
        if self.in_startup {
            if !self
                .synchronization_config
                .startup_step_panic_threshold
                .is_within(change)
            {
                error!("Unusually large clock step suggested, please manually verify system clock and reference clock state and restart if appropriate.");
                #[cfg(not(test))]
                std::process::exit(crate::exitcode::SOFTWARE);
                #[cfg(test)]
                panic!("Threshold exceeded");
            }
        } else {
            self.timedata.accumulated_steps += change.abs();
            if !self
                .synchronization_config
                .single_step_panic_threshold
                .is_within(change)
                || self
                    .synchronization_config
                    .accumulated_step_panic_threshold
                    .map(|v| self.timedata.accumulated_steps > v)
                    .unwrap_or(false)
            {
                error!("Unusually large clock step suggested, please manually verify system clock and reference clock state and restart if appropriate.");
                #[cfg(not(test))]
                std::process::exit(crate::exitcode::SOFTWARE);
                #[cfg(test)]
                panic!("Threshold exceeded");
            }
        }
    }

    fn steer_offset(&mut self, change: f64, freq_delta: f64) -> Option<Duration> {
        if change.abs() > self.algo_config.step_threshold {
            // jump
            self.check_offset_steer(change);
            self.clock
                .step_clock(NtpDuration::from_seconds(change))
                .expect("Cannot adjust clock");
            for (state, _) in self.sources.values_mut() {
                state.process_offset_steering(change);
            }
            info!("Jumped offset by {}ms", change * 1e3);
            None
        } else {
            // start slew
            let freq = self
                .algo_config
                .slew_maximum_frequency_offset
                .min(change.abs() / self.algo_config.slew_minimum_duration);
            let duration = Duration::from_secs_f64(change.abs() / freq);
            info!(
                "Slewing by {}ms over {}s",
                change * 1e3,
                duration.as_secs_f64(),
            );
            self.change_desired_frequency(-freq * change.signum(), freq_delta);
            Some(duration)
        }
    }

    fn change_desired_frequency(&mut self, new_freq: f64, freq_delta: f64) -> NtpTimestamp {
        let change = self.desired_freq - new_freq + freq_delta;
        self.desired_freq = new_freq;
        self.steer_frequency(change)
    }

    fn steer_frequency(&mut self, change: f64) -> NtpTimestamp {
        let new_freq_offset = ((1.0 + self.freq_offset) * (1.0 + change) - 1.0).clamp(
            -self.algo_config.maximum_frequency_steer,
            self.algo_config.maximum_frequency_steer,
        );
        let actual_change = (1.0 + new_freq_offset) / (1.0 + self.freq_offset) - 1.0;
        self.freq_offset = new_freq_offset;
        let freq_update = self
            .clock
            .set_frequency(self.freq_offset)
            .expect("Cannot adjust clock");
        for (state, _) in self.sources.values_mut() {
            state.process_frequency_steering(freq_update, actual_change);
        }
        info!(
            "Changed frequency, current steer {}ppm, desired freq {}ppm",
            self.freq_offset * 1e6,
            self.desired_freq * 1e6,
        );
        freq_update
    }

    fn update_desired_poll(&mut self) {
        self.timedata.poll_interval = self
            .sources
            .values()
            .map(|(state, _)| {
                state.get_desired_poll(&self.source_defaults_config.poll_interval_limits)
            })
            .min()
            .unwrap_or(self.source_defaults_config.poll_interval_limits.max);
    }
}

impl<C: NtpClock, SourceId: Hash + Eq + Copy + Debug> TimeSyncController<C, SourceId>
    for KalmanClockController<C, SourceId>
{
    type AlgorithmConfig = AlgorithmConfig;

    fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algo_config: Self::AlgorithmConfig,
        pps_source_id: Option<SourceId>,
    ) -> Result<Self, C::Error> {
        // Setup clock
        clock.disable_ntp_algorithm()?;
        clock.status_update(NtpLeapIndicator::Unknown)?;
        clock.set_frequency(0.0)?;

        Ok(KalmanClockController {
            sources: HashMap::new(),
            clock,
            synchronization_config,
            source_defaults_config,
            algo_config,
            freq_offset: 0.0,
            desired_freq: 0.0,
            timedata: TimeSnapshot::default(),
            in_startup: true,
            pps_source_id,
        })
    }

    fn update_config(
        &mut self,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algo_config: Self::AlgorithmConfig,
    ) {
        self.synchronization_config = synchronization_config;
        self.source_defaults_config = source_defaults_config;
        self.algo_config = algo_config;
    }

    fn add_source(&mut self, id: SourceId) {
        self.sources.insert(id, (SourceState::new(), false));
    }

    fn remove_source(&mut self, id: SourceId) {
        self.sources.remove(&id);
    }

    fn source_update(&mut self, id: SourceId, usable: bool) {
        if let Some(state) = self.sources.get_mut(&id) {
            state.1 = usable;
        }
    }

    fn source_pps_update(&mut self, id: SourceId, usable: bool) {
        if let Some(state) = self.sources.get_mut(&id) {
            state.1 = usable;
        }
    }

    fn source_measurement(
        &mut self,
        id: SourceId,
        measurement: Measurement,
    ) -> StateUpdate<SourceId> {

        let should_update_clock = self.update_source(id, measurement);
        self.update_desired_poll();
        if should_update_clock {
            self.update_clock(measurement.localtime)
        } else {
            StateUpdate {
                used_sources: None,
                time_snapshot: Some(self.timedata),
                next_update: None,
            }
        }
    }

    fn source_pps_measurement(
        &mut self,
        id: SourceId,
        measurement: Measurement,
    ) -> StateUpdate<SourceId> {

        let should_update_clock = self.update_source(id, measurement);
        self.update_desired_poll();
        if should_update_clock {
            self.update_clock(measurement.localtime)
        } else {
            StateUpdate {
                used_sources: None,
                time_snapshot: Some(self.timedata),
                next_update: None,
            }
        }
    }

    fn time_update(&mut self) -> StateUpdate<SourceId> {
        // End slew
        self.change_desired_frequency(0.0, 0.0);
        StateUpdate::default()
    }

    fn source_snapshot(&self, id: SourceId) -> Option<ObservableSourceTimedata> {
        self.sources
            .get(&id)
            .and_then(|v| v.0.snapshot(id))
            .map(|v| v.observe())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use crate::config::StepThreshold;
    use crate::time_types::NtpInstant;

    use super::*;

    #[derive(Debug, Clone)]
    struct TestClock {
        has_steered: RefCell<bool>,
        current_time: NtpTimestamp,
    }

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> Result<NtpTimestamp, Self::Error> {
            Ok(self.current_time)
        }

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            *self.has_steered.borrow_mut() = true;
            Ok(self.current_time)
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            *self.has_steered.borrow_mut() = true;
            Ok(self.current_time)
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _maximum_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_startup_flag_unsets() {
        let synchronization_config = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..SynchronizationConfig::default()
        };
        let algo_config = AlgorithmConfig::default();
        let source_defaults_config = SourceDefaultsConfig::default();
        let mut algo = KalmanClockController::new(
            TestClock {
                has_steered: RefCell::new(false),
                current_time: NtpTimestamp::from_fixed_int(0),
            },
            synchronization_config,
            source_defaults_config,
            algo_config,
            None,
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        algo.add_source(0);
        algo.source_update(0, true);

        assert!(algo.in_startup);

        let mut noise = 1e-9;

        while !*algo.clock.has_steered.borrow() {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1.0);
            noise += 1e-9;
            algo.source_measurement(
                0,
                Measurement {
                    delay: NtpDuration::from_seconds(0.001 + noise),
                    offset: NtpDuration::from_seconds(1700.0 + noise),
                    transmit_timestamp: Default::default(),
                    receive_timestamp: Default::default(),
                    localtime: algo.clock.current_time,
                    monotime: cur_instant,

                    stratum: 0,
                    root_delay: NtpDuration::default(),
                    root_dispersion: NtpDuration::default(),
                    leap: NtpLeapIndicator::NoWarning,
                    precision: 0,
                    gps: None,
                    pps: None,
                },
            );
        }

        assert!(!algo.in_startup);
        assert_eq!(algo.timedata.leap_indicator, NtpLeapIndicator::NoWarning);
        assert_ne!(algo.timedata.root_delay, NtpDuration::ZERO);
        assert_ne!(algo.timedata.root_dispersion, NtpDuration::ZERO);
    }

    #[test]
    fn slews_dont_accumulate() {
        let synchronization_config = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            single_step_panic_threshold: StepThreshold {
                forward: None,
                backward: None,
            },
            ..SynchronizationConfig::default()
        };
        let algo_config = AlgorithmConfig {
            step_threshold: 1800.0,
            ..Default::default()
        };
        let source_defaults_config = SourceDefaultsConfig::default();
        let mut algo = KalmanClockController::<_, u32>::new(
            TestClock {
                has_steered: RefCell::new(false),
                current_time: NtpTimestamp::from_fixed_int(0),
            },
            synchronization_config,
            source_defaults_config,
            algo_config,
            None,
        )
        .unwrap();

        algo.in_startup = false;
        algo.steer_offset(1000.0, 0.0);
        assert_eq!(algo.timedata.accumulated_steps, NtpDuration::ZERO);
    }

    #[test]
    #[should_panic]
    fn jumps_add_absolutely() {
        let synchronization_config = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            single_step_panic_threshold: StepThreshold {
                forward: None,
                backward: None,
            },
            accumulated_step_panic_threshold: Some(NtpDuration::from_seconds(1800.0)),
            ..SynchronizationConfig::default()
        };
        let algo_config = AlgorithmConfig::default();
        let source_defaults_config = SourceDefaultsConfig::default();
        let mut algo = KalmanClockController::<_, u32>::new(
            TestClock {
                has_steered: RefCell::new(false),
                current_time: NtpTimestamp::from_fixed_int(0),
            },
            synchronization_config,
            source_defaults_config,
            algo_config,
            None,
        )
        .unwrap();

        algo.in_startup = false;
        algo.steer_offset(1000.0, 0.0);
        algo.steer_offset(-1000.0, 0.0);
    }

    #[test]
    #[should_panic]
    fn test_large_offset_eventually_panics() {
        let synchronization_config = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..SynchronizationConfig::default()
        };
        let algo_config = AlgorithmConfig::default();
        let source_defaults_config = SourceDefaultsConfig::default();
        let mut algo = KalmanClockController::new(
            TestClock {
                has_steered: RefCell::new(false),
                current_time: NtpTimestamp::from_fixed_int(0),
            },
            synchronization_config,
            source_defaults_config,
            algo_config,
            None,
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        algo.add_source(0);
        algo.source_update(0, true);

        let mut noise = 1e-9;

        loop {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1.0);
            noise += 1e-9;
            algo.source_measurement(
                0,
                Measurement {
                    delay: NtpDuration::from_seconds(0.001 + noise),
                    offset: NtpDuration::from_seconds(1700.0 + noise),
                    transmit_timestamp: Default::default(),
                    receive_timestamp: Default::default(),
                    localtime: algo.clock.current_time,
                    monotime: cur_instant,

                    stratum: 0,
                    root_delay: NtpDuration::default(),
                    root_dispersion: NtpDuration::default(),
                    leap: NtpLeapIndicator::NoWarning,
                    precision: 0,
                    gps: None,
                    pps: None,
                },
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_backward_step_panics_before_steer() {
        let synchronization_config = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            startup_step_panic_threshold: StepThreshold {
                forward: None,
                backward: Some(NtpDuration::from_seconds(1800.)),
            },
            ..SynchronizationConfig::default()
        };
        let algo_config = AlgorithmConfig::default();
        let source_defaults_config = SourceDefaultsConfig::default();
        let mut algo = KalmanClockController::new(
            TestClock {
                has_steered: RefCell::new(false),
                current_time: NtpTimestamp::from_fixed_int(0),
            },
            synchronization_config,
            source_defaults_config,
            algo_config,
            None,
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        algo.add_source(0);
        algo.source_update(0, true);

        let mut noise = 1e-9;

        while !*algo.clock.has_steered.borrow() {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1.0);
            noise *= -1.0;
            algo.source_measurement(
                0,
                Measurement {
                    delay: NtpDuration::from_seconds(0.001 + noise),
                    offset: NtpDuration::from_seconds(-3600.0 + noise),
                    transmit_timestamp: Default::default(),
                    receive_timestamp: Default::default(),
                    localtime: algo.clock.current_time,
                    monotime: cur_instant,

                    stratum: 0,
                    root_delay: NtpDuration::default(),
                    root_dispersion: NtpDuration::default(),
                    leap: NtpLeapIndicator::NoWarning,
                    precision: 0,
                    gps: None,
                    pps: None,
                },
            );
        }
    }
}
