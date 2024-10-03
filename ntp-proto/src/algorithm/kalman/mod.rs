use std::{collections::HashMap, fmt::Debug, hash::Hash, time::Duration};

pub use source::AveragingBuffer;
use tracing::{debug, error, info};

use crate::{
    clock::NtpClock,
    config::{SourceDefaultsConfig, SynchronizationConfig},
    packet::NtpLeapIndicator,
    system::TimeSnapshot,
    time_types::{NtpDuration, NtpTimestamp},
};

use self::{combiner::combine, config::AlgorithmConfig, source::KalmanState};

use super::{ObservableSourceTimedata, StateUpdate, TimeSyncController};

mod combiner;
pub(super) mod config;
mod matrix;
mod select;
mod source;

pub use source::KalmanSourceController;

fn sqr(x: f64) -> f64 {
    x * x
}

#[derive(Debug, Clone, Copy)]
struct SourceSnapshot<Index: Copy> {
    index: Index,
    state: KalmanState,
    wander: f64,
    delay: f64,

    source_uncertainty: NtpDuration,
    source_delay: NtpDuration,
    leap_indicator: NtpLeapIndicator,

    last_update: NtpTimestamp,
}

impl<Index: Copy> SourceSnapshot<Index> {
    fn offset(&self) -> f64 {
        self.state.offset()
    }

    fn offset_uncertainty(&self) -> f64 {
        self.state.offset_variance().sqrt()
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
pub struct KalmanControllerMessage {
    inner: KalmanControllerMessageInner,
}

#[derive(Debug, Clone)]
enum KalmanControllerMessageInner {
    Step { steer: f64 },
    FreqChange { steer: f64, time: NtpTimestamp },
}

#[derive(Debug, Clone, Copy)]
pub struct KalmanSourceMessage<SourceId: Copy> {
    inner: SourceSnapshot<SourceId>,
}

#[derive(Debug, Clone)]
pub struct KalmanClockController<C: NtpClock, SourceId: Hash + Eq + Copy + Debug> {
    sources: HashMap<SourceId, (Option<SourceSnapshot<SourceId>>, bool)>,
    clock: C,
    synchronization_config: SynchronizationConfig,
    source_defaults_config: SourceDefaultsConfig,
    algo_config: AlgorithmConfig,
    freq_offset: f64,
    timedata: TimeSnapshot,
    desired_freq: f64,
    in_startup: bool,
}

impl<C: NtpClock, SourceId: Hash + Eq + Copy + Debug> KalmanClockController<C, SourceId> {
    fn update_clock(
        &mut self,
        time: NtpTimestamp,
    ) -> StateUpdate<SourceId, KalmanControllerMessage> {
        // ensure all filters represent the same (current) time
        if self
            .sources
            .iter()
            .filter_map(|(_, (state, _))| state.map(|v| v.state.time))
            .any(|sourcetime| time - sourcetime < NtpDuration::ZERO)
        {
            return StateUpdate {
                source_message: None,
                used_sources: None,
                time_snapshot: Some(self.timedata),
                next_update: None,
            };
        }
        for (_, (state, _)) in self.sources.iter_mut() {
            if let Some(ref mut snapshot) = state {
                snapshot.state = snapshot.state.progress_time(time, snapshot.wander)
            }
        }

        let selection = select::select(
            &self.synchronization_config,
            &self.algo_config,
            self.sources
                .iter()
                .filter_map(
                    |(_, (state, usable))| {
                        if *usable {
                            state.as_ref()
                        } else {
                            None
                        }
                    },
                )
                .cloned()
                .collect(),
        );

        if let Some(combined) = combine(&selection, &self.algo_config) {
            info!(
                "Offset: {}+-{}ms, frequency: {}+-{}ppm",
                combined.estimate.offset() * 1e3,
                combined.estimate.offset_variance().sqrt() * 1e3,
                combined.estimate.frequency() * 1e6,
                combined.estimate.frequency_variance().sqrt() * 1e6
            );

            if self.in_startup {
                self.clock
                    .disable_ntp_algorithm()
                    .expect("Cannot update clock");
            }

            let freq_delta = combined.estimate.frequency() - self.desired_freq;
            let freq_uncertainty = combined.estimate.frequency_variance().sqrt();
            let offset_delta = combined.estimate.offset();
            let offset_uncertainty = combined.estimate.offset_variance().sqrt();
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
                )
            } else {
                StateUpdate::default()
            };

            self.timedata.root_delay = combined.delay;
            self.timedata.root_dispersion =
                NtpDuration::from_seconds(combined.estimate.offset_variance().sqrt());
            self.clock
                .error_estimate_update(self.timedata.root_dispersion, self.timedata.root_delay)
                .expect("Cannot update clock");

            if let Some(leap) = combined.leap_indicator {
                self.clock.status_update(leap).expect("Cannot update clock");
                self.timedata.leap_indicator = leap;
            }

            // After a successful measurement we are out of startup.
            self.in_startup = false;

            StateUpdate {
                used_sources: Some(combined.sources),
                time_snapshot: Some(self.timedata),
                ..next_update
            }
        } else {
            info!("No consensus on current time");
            StateUpdate {
                time_snapshot: Some(self.timedata),
                ..StateUpdate::default()
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

    fn steer_offset(
        &mut self,
        change: f64,
        freq_delta: f64,
    ) -> StateUpdate<SourceId, KalmanControllerMessage> {
        if change.abs() > self.algo_config.step_threshold {
            // jump
            self.check_offset_steer(change);
            self.clock
                .step_clock(NtpDuration::from_seconds(change))
                .expect("Cannot adjust clock");
            for (state, _) in self.sources.values_mut() {
                if let Some(ref mut state) = state {
                    state.state = state.state.process_offset_steering(change);
                }
            }
            info!("Jumped offset by {}ms", change * 1e3);
            StateUpdate {
                source_message: Some(KalmanControllerMessage {
                    inner: KalmanControllerMessageInner::Step { steer: change },
                }),
                ..StateUpdate::default()
            }
        } else {
            // start slew
            let freq = self
                .algo_config
                .slew_maximum_frequency_offset
                .min(change.abs() / self.algo_config.slew_minimum_duration);
            let duration = Duration::from_secs_f64(change.abs() / freq);
            debug!(
                "Slewing by {}ms over {}s",
                change * 1e3,
                duration.as_secs_f64(),
            );
            let update = self.change_desired_frequency(-freq * change.signum(), freq_delta);
            StateUpdate {
                next_update: Some(duration),
                ..update
            }
        }
    }

    fn change_desired_frequency(
        &mut self,
        new_freq: f64,
        freq_delta: f64,
    ) -> StateUpdate<SourceId, KalmanControllerMessage> {
        let change = self.desired_freq - new_freq + freq_delta;
        self.desired_freq = new_freq;
        self.steer_frequency(change)
    }

    fn steer_frequency(&mut self, change: f64) -> StateUpdate<SourceId, KalmanControllerMessage> {
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
            if let Some(ref mut state) = state {
                state.state =
                    state
                        .state
                        .process_frequency_steering(freq_update, actual_change, state.wander)
            }
        }
        debug!(
            "Changed frequency, current steer {}ppm, desired freq {}ppm",
            self.freq_offset * 1e6,
            self.desired_freq * 1e6,
        );
        StateUpdate {
            source_message: Some(KalmanControllerMessage {
                inner: KalmanControllerMessageInner::FreqChange {
                    steer: actual_change,
                    time: freq_update,
                },
            }),
            ..StateUpdate::default()
        }
    }
}

impl<C: NtpClock, SourceId: Hash + Eq + Copy + Debug + Send + 'static> TimeSyncController
    for KalmanClockController<C, SourceId>
{
    type Clock = C;
    type SourceId = SourceId;
    type AlgorithmConfig = AlgorithmConfig;
    type ControllerMessage = KalmanControllerMessage;
    type SourceMessage = KalmanSourceMessage<SourceId>;
    type NtpSourceController = KalmanSourceController<SourceId, NtpDuration, AveragingBuffer>;
    type SockSourceController = KalmanSourceController<SourceId, (), f64>;

    fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        source_defaults_config: SourceDefaultsConfig,
        algo_config: Self::AlgorithmConfig,
    ) -> Result<Self, C::Error> {
        // Setup clock
        let freq_offset = clock.get_frequency()?;

        Ok(KalmanClockController {
            sources: HashMap::new(),
            clock,
            synchronization_config,
            source_defaults_config,
            algo_config,
            freq_offset,
            desired_freq: 0.0,
            timedata: TimeSnapshot::default(),
            in_startup: true,
        })
    }

    fn take_control(&mut self) -> Result<(), <C as NtpClock>::Error> {
        self.clock.disable_ntp_algorithm()?;
        self.clock.status_update(NtpLeapIndicator::Unknown)?;
        Ok(())
    }

    fn add_source(&mut self, id: SourceId) -> Self::NtpSourceController {
        self.sources.insert(id, (None, false));
        KalmanSourceController::new(
            id,
            self.algo_config,
            self.source_defaults_config,
            AveragingBuffer::default(),
        )
    }

    fn add_sock_source(
        &mut self,
        id: SourceId,
        measurement_noise_estimate: f64,
    ) -> Self::SockSourceController {
        self.sources.insert(id, (None, false));
        KalmanSourceController::new(
            id,
            self.algo_config,
            self.source_defaults_config,
            measurement_noise_estimate,
        )
    }

    fn remove_source(&mut self, id: SourceId) {
        self.sources.remove(&id);
    }

    fn source_update(&mut self, id: SourceId, usable: bool) {
        if let Some(state) = self.sources.get_mut(&id) {
            state.1 = usable;
        }
    }
    fn time_update(&mut self) -> StateUpdate<SourceId, Self::ControllerMessage> {
        // End slew
        self.change_desired_frequency(0.0, 0.0)
    }

    fn source_message(
        &mut self,
        id: SourceId,
        message: Self::SourceMessage,
    ) -> StateUpdate<SourceId, Self::ControllerMessage> {
        if let Some(source) = self.sources.get_mut(&id) {
            let time = message.inner.last_update;
            source.0 = Some(message.inner);
            self.update_clock(time)
        } else {
            error!("Internal error: Update from non-existing source");
            StateUpdate::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use matrix::{Matrix, Vector};

    use crate::config::StepThreshold;
    use crate::source::Measurement;
    use crate::time_types::NtpInstant;
    use crate::SourceController;

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

        fn get_frequency(&self) -> Result<f64, Self::Error> {
            Ok(0.0)
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
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        let mut source = algo.add_source(0);
        algo.source_update(0, true);

        assert!(algo.in_startup);

        let mut noise = 1e-9;

        while !*algo.clock.has_steered.borrow() {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1.0);
            noise += 1e-9;

            let message = source.handle_measurement(Measurement {
                delay: NtpDuration::from_seconds(0.001 + noise),
                offset: NtpDuration::from_seconds(1700.0 + noise),
                localtime: algo.clock.current_time,
                monotime: cur_instant,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            });
            if let Some(message) = message {
                let actions = algo.source_message(0, message);
                if let Some(source_message) = actions.source_message {
                    source.handle_message(source_message);
                }
            }
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
        )
        .unwrap();

        algo.in_startup = false;
        algo.steer_offset(1000.0, 0.0);
        algo.steer_offset(-1000.0, 0.0);
    }

    #[test]
    fn test_jumps_update_state() {
        let synchronization_config = SynchronizationConfig::default();
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
        )
        .unwrap();

        algo.sources.insert(
            0,
            (
                Some(SourceSnapshot {
                    index: 0,
                    state: KalmanState {
                        state: Vector::new_vector([0.0, 0.0]),
                        uncertainty: Matrix::new([[1e-18, 0.0], [0.0, 1e-18]]),
                        time: NtpTimestamp::from_fixed_int(0),
                    },
                    wander: 0.0,
                    delay: 0.0,
                    source_uncertainty: NtpDuration::ZERO,
                    source_delay: NtpDuration::ZERO,
                    leap_indicator: NtpLeapIndicator::NoWarning,
                    last_update: NtpTimestamp::from_fixed_int(0),
                }),
                true,
            ),
        );

        algo.steer_offset(100.0, 0.0);
        assert_eq!(
            algo.sources.get(&0).unwrap().0.unwrap().state.offset(),
            -100.0
        );
        assert_eq!(
            algo.sources.get(&0).unwrap().0.unwrap().state.time,
            NtpTimestamp::from_seconds_nanos_since_ntp_era(100, 0)
        );
    }

    #[test]
    fn test_freqsteer_update_state() {
        let synchronization_config = SynchronizationConfig::default();
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
        )
        .unwrap();

        algo.sources.insert(
            0,
            (
                Some(SourceSnapshot {
                    index: 0,
                    state: KalmanState {
                        state: Vector::new_vector([0.0, 0.0]),
                        uncertainty: Matrix::new([[1e-18, 0.0], [0.0, 1e-18]]),
                        time: NtpTimestamp::from_fixed_int(0),
                    },
                    wander: 0.0,
                    delay: 0.0,
                    source_uncertainty: NtpDuration::ZERO,
                    source_delay: NtpDuration::ZERO,
                    leap_indicator: NtpLeapIndicator::NoWarning,
                    last_update: NtpTimestamp::from_fixed_int(0),
                }),
                true,
            ),
        );

        algo.steer_frequency(1e-6);
        assert!(algo.sources.get(&0).unwrap().0.unwrap().state.frequency() - -1e-6 < 1e-12);
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
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        let mut source = algo.add_source(0);
        algo.source_update(0, true);

        let mut noise = 1e-9;

        loop {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1800.0);
            noise += 1e-9;

            let message = source.handle_measurement(Measurement {
                delay: NtpDuration::from_seconds(0.001 + noise),
                offset: NtpDuration::from_seconds(1700.0 + noise),
                localtime: algo.clock.current_time,
                monotime: cur_instant,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            });
            if let Some(message) = message {
                let actions = algo.source_message(0, message);
                if let Some(source_message) = actions.source_message {
                    source.handle_message(source_message);
                }
            }
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
        )
        .unwrap();
        let mut cur_instant = NtpInstant::now();

        // ignore startup steer of frequency.
        *algo.clock.has_steered.borrow_mut() = false;

        let mut source = algo.add_source(0);
        algo.source_update(0, true);

        let mut noise = 1e-9;

        while !*algo.clock.has_steered.borrow() {
            cur_instant = cur_instant + std::time::Duration::from_secs(1);
            algo.clock.current_time += NtpDuration::from_seconds(1.0);
            noise *= -1.0;

            let message = source.handle_measurement(Measurement {
                delay: NtpDuration::from_seconds(0.001 + noise),
                offset: NtpDuration::from_seconds(-3600.0 + noise),
                localtime: algo.clock.current_time,
                monotime: cur_instant,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            });
            if let Some(message) = message {
                let actions = algo.source_message(0, message);
                if let Some(source_message) = actions.source_message {
                    source.handle_message(source_message);
                }
            }
        }
    }
}
