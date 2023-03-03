use crate::{
    packet::NtpLeapIndicator, time_types::PollInterval, NtpClock, NtpDuration, NtpInstant,
    SystemConfig, TimeSnapshot,
};
use tracing::{debug, error, info, instrument, trace};

use super::config::AlgorithmConfig;

/// Jitter averaging factor
const JITTER_AVG: f64 = 4.;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ClockState {
    StartupBlank,
    // Needed when implementing frequency backups
    #[allow(dead_code)]
    StartupFreq,
    MeasureFreq,
    Spike,
    Sync,
}

/// Controller responsible for actually
/// deciding which adjustments to make based
/// on results from the filtering and
/// combining algorithms.
#[derive(Debug, Copy, Clone)]
pub(super) struct ClockController<C: NtpClock> {
    clock: C,
    state: ClockState,
    last_update_time: NtpInstant,
    preferred_poll_interval: PollInterval,
    poll_interval_counter: i32,
    offset: NtpDuration,
    jitter: NtpDuration,
    accumulated_steps: NtpDuration,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum ClockUpdateResult {
    Ignore,
    Step,
    Slew,
    Panic,
}

impl<C: NtpClock> ClockController<C> {
    pub fn new(clock: C, system: &TimeSnapshot, config: &SystemConfig) -> Self {
        if let Err(e) = clock.enable_ntp_algorithm() {
            error!(error = %e, "Could not enable ntp kernel clock discipline");
            std::process::exit(exitcode::NOPERM);
        }
        if let Err(e) = clock.set_frequency(0.) {
            error!(error = %e, "Could not set clock frequency, exiting");
            std::process::exit(exitcode::NOPERM);
        }
        Self {
            clock,
            state: ClockState::StartupBlank,
            // Setting up the clock counts as an update for
            // the purposes of the math done here
            last_update_time: NtpInstant::now(),
            preferred_poll_interval: config.initial_poll,
            poll_interval_counter: 0,
            offset: NtpDuration::ZERO,
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        }
    }

    // Preferred ratio between measured offset
    // and measurement jitter
    const POLL_FACTOR: i8 = 4;
    // Threshold for changing desired poll interval
    const POLL_ADJUST: i32 = 30;

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "debug", skip(self))]
    pub fn update(
        &mut self,
        config: &SystemConfig,
        algo_config: &AlgorithmConfig,
        system: &TimeSnapshot,
        offset: NtpDuration,
        root_delay: NtpDuration,
        root_dispersion: NtpDuration,
        leap_status: NtpLeapIndicator,
        last_peer_update: NtpInstant,
    ) -> ClockUpdateResult {
        // Check that we have a somewhat reasonable result
        if self.offset_too_large(config, offset) {
            error!("Detected overly large offset");
            return ClockUpdateResult::Panic;
        }

        if self.combined_steps_too_large(config, offset) {
            error!("Current offset too large combined with previously made steps");
            return ClockUpdateResult::Panic;
        }

        // Main decision making
        //
        // Combined, this code is responsible for:
        //  - Filtering large but temporary spikes in the measured
        //    offset to our timeservers
        //  - Stepping the clock if a large difference persists long
        //    enough
        //  - Ensuring a proper initial frequency measurement on startup
        //  - Making small (gradual) adjustments to the clock when we
        //    only have a small error
        if offset.abs() > NtpDuration::STEP_THRESHOLD {
            // Large spikes are filtered initialy (to handle weird but temporary network issues)
            // and then handled by stepping if they persist.
            match self.state {
                ClockState::Sync => {
                    info!("Spike detected");
                    self.state = ClockState::Spike;
                    return ClockUpdateResult::Ignore;
                }
                ClockState::MeasureFreq => {
                    if NtpInstant::abs_diff(last_peer_update, self.last_update_time)
                        < algo_config.frequency_measurement_period
                    {
                        // Initial frequency measurement needs some time
                        debug!("Frequency measurement not finished yet");
                        return ClockUpdateResult::Ignore;
                    }

                    self.set_freq(offset, last_peer_update);
                    return self.do_step(offset, last_peer_update, system.precision, config);
                }
                ClockState::Spike => {
                    if NtpInstant::abs_diff(last_peer_update, self.last_update_time)
                        < algo_config.spike_threshold
                    {
                        // Filter out short spikes
                        debug!("Spike continues");
                        return ClockUpdateResult::Ignore;
                    }

                    // Seems that the large difference reflects reality, since
                    // it persisted for a significant amount of time. So step
                    // the clock
                    return self.do_step(offset, last_peer_update, system.precision, config);
                }
                ClockState::StartupBlank | ClockState::StartupFreq => {
                    // In fully non-synchronized states, doing the jump
                    // immediately is fine, as we expect the clock to
                    // be off significantly
                    return self.do_step(offset, last_peer_update, system.precision, config);
                }
            }
        } else {
            match self.state {
                ClockState::StartupBlank => {
                    // Even though we have a small offset, making a step here
                    // is the easiest way to get into a proper state.
                    //
                    // Using slew might result in us also accidentaly
                    // moving away from the freq=0 initialization done earlier,
                    // ruining the frequency measurement coming after.
                    return self.do_step(offset, last_peer_update, system.precision, config);
                }
                ClockState::MeasureFreq => {
                    if NtpInstant::abs_diff(last_peer_update, self.last_update_time)
                        < algo_config.frequency_measurement_period
                    {
                        // Initial frequency measurement needs some time
                        debug!("Frequency measurement not finished yet");
                        return ClockUpdateResult::Ignore;
                    }

                    self.set_freq(offset, last_peer_update);
                    self.offset = offset;
                    self.last_update_time = last_peer_update;
                    self.state = ClockState::Sync;
                }
                ClockState::StartupFreq | ClockState::Sync | ClockState::Spike => {
                    // Just make the small adjustment needed, we are good

                    // Since we currently only support the kernel api interface,
                    // we do not need to calculate frequency changes here, the
                    // kernel will do that for us.

                    let etemp_root = self.jitter.to_seconds();
                    let etemp = etemp_root * etemp_root;
                    let dtemp_root = f64::max(
                        system.precision.to_seconds(),
                        (offset.to_seconds() - self.offset.to_seconds()).abs(),
                    );
                    let dtemp = dtemp_root * dtemp_root;
                    self.jitter =
                        NtpDuration::from_seconds((etemp + (dtemp - etemp) / JITTER_AVG).sqrt());
                    self.offset = offset;
                    self.last_update_time = last_peer_update;
                    self.state = ClockState::Sync;
                }
            }
        }

        // It is reasonable to panic here, as there is very little we can
        // be expected to do if the clock is not amenable to change
        let result = self
            .clock
            .ntp_algorithm_update(self.offset, self.preferred_poll_interval)
            .and_then(|_| {
                self.clock
                    .error_estimate_update(self.jitter, root_delay / 2 + root_dispersion)
            })
            .and_then(|_| self.clock.status_update(leap_status));
        if let Err(e) = result {
            error!(error = %e, "Failed to update the clock, exiting");
            std::process::exit(exitcode::NOPERM);
        }

        // Adjust whether we would prefer to have a longer or shorter
        // poll interval depending on the amount of jitter
        // Note, our behaviour matches the code skeleton of rfc5905
        // fully, instead of the main text on page 50. This is needed
        // to improve responsiveness to upset events.
        if self.offset.abs() < self.jitter * Self::POLL_FACTOR {
            self.poll_interval_counter += self.preferred_poll_interval.as_log() as i32;
        } else {
            self.poll_interval_counter -= 2 * (self.preferred_poll_interval.as_log() as i32);
        }

        trace!(
            counter = debug(self.poll_interval_counter),
            "Poll preference"
        );

        // If our preference becomes strong enough, adjust poll interval
        // and reset. The hysteresis here ensures we aren't constantly flip-flopping
        // between different preferred interval lengths.
        if self.poll_interval_counter > Self::POLL_ADJUST {
            self.poll_interval_counter = 0;
            self.preferred_poll_interval = self.preferred_poll_interval.inc(config.poll_limits);
            debug!(
                poll_interval = debug(self.preferred_poll_interval),
                "Increased system poll interval"
            );
        }
        if self.poll_interval_counter < -Self::POLL_ADJUST {
            self.poll_interval_counter = 0;
            self.preferred_poll_interval = self.preferred_poll_interval.dec(config.poll_limits);
            debug!(
                poll_interval = debug(self.preferred_poll_interval),
                "Decreased system poll interval"
            );
        }

        info!(offset = debug(offset), "Slewed clock");
        ClockUpdateResult::Slew
    }

    pub fn preferred_poll_interval(&self) -> PollInterval {
        self.preferred_poll_interval
    }

    pub fn accumulated_steps(&self) -> NtpDuration {
        self.accumulated_steps
    }

    pub fn offset(&self) -> NtpDuration {
        self.offset
    }

    pub fn jitter(&self) -> NtpDuration {
        self.jitter
    }

    fn offset_too_large(&self, config: &SystemConfig, offset: NtpDuration) -> bool {
        let threshold = match self.state {
            // The system might be wildly off on startup
            //  so the accepted step size is different then
            ClockState::StartupBlank | ClockState::StartupFreq => config.startup_panic_threshold,
            _ => config.panic_threshold,
        };

        !threshold.is_within(offset)
    }

    fn combined_steps_too_large(&self, config: &SystemConfig, offset: NtpDuration) -> bool {
        if matches!(
            self.state,
            ClockState::StartupBlank | ClockState::StartupFreq
        ) {
            return false;
        }
        if let Some(threshold) = config.accumulated_threshold {
            offset.abs() + self.accumulated_steps > threshold
        } else {
            false
        }
    }

    fn do_step(
        &mut self,
        offset: NtpDuration,
        last_peer_update: NtpInstant,
        precision: NtpDuration,
        config: &SystemConfig,
    ) -> ClockUpdateResult {
        info!(offset = debug(offset), "Stepping clock");
        self.poll_interval_counter = 0;
        self.preferred_poll_interval = config.initial_poll;
        // It is reasonable to panic here, as there is very little we can
        // be expected to do if the clock is not amenable to change
        if let Err(e) = self.clock.step_clock(offset) {
            error!(error = %e, "Could not step the clock, exiting");
            std::process::exit(exitcode::NOPERM);
        }
        self.offset = NtpDuration::ZERO;
        self.jitter = precision;
        self.last_update_time = last_peer_update;
        self.state = match self.state {
            ClockState::StartupBlank => ClockState::MeasureFreq,
            _ => ClockState::Sync,
        };
        if !matches!(
            self.state,
            ClockState::StartupBlank | ClockState::StartupFreq
        ) {
            self.accumulated_steps += offset.abs();
        }
        ClockUpdateResult::Step
    }

    fn set_freq(&mut self, offset: NtpDuration, last_peer_update: NtpInstant) {
        info!(
            freq = display(
                offset.to_seconds()
                    / NtpInstant::abs_diff(last_peer_update, self.last_update_time).to_seconds()
            ),
            "Setting initial frequency"
        );
        let result = self.clock.set_frequency(
            offset.to_seconds()
                / NtpInstant::abs_diff(last_peer_update, self.last_update_time).to_seconds(),
        );
        if let Err(e) = result {
            error!(error = %e, "Unable to adjust clock frequency, exiting");
            std::process::exit(exitcode::NOPERM);
        }
    }

    /// Are we still gathering initial samples?
    pub fn is_startup(&self) -> bool {
        matches!(self.state, ClockState::StartupBlank)
    }

    /// Are we still gathering frequency data?
    pub fn is_measuring_frequency(&self) -> bool {
        matches!(self.state, ClockState::MeasureFreq)
    }
}

#[cfg(test)]
mod tests {
    use crate::{time_types::PollIntervalLimits, NtpTimestamp};

    use super::*;
    use core::cell::RefCell;
    use std::time::Duration;

    #[derive(Debug, Clone, Default)]
    struct TestClock {
        last_freq: RefCell<Option<f64>>,
        last_offset: RefCell<Option<NtpDuration>>,
        last_est_error: RefCell<Option<NtpDuration>>,
        last_max_error: RefCell<Option<NtpDuration>>,
        last_poll_interval: RefCell<Option<PollInterval>>,
        last_leap_status: RefCell<Option<NtpLeapIndicator>>,
        last_ntp_discipline_enabled: RefCell<Option<bool>>,
    }

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn set_frequency(&self, freq: f64) -> Result<NtpTimestamp, Self::Error> {
            *self.last_freq.borrow_mut() = Some(freq);
            Ok(NtpTimestamp::from_fixed_int(0))
        }

        fn step_clock(&self, offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            *self.last_offset.borrow_mut() = Some(offset);
            Ok(NtpTimestamp::from_fixed_int(0))
        }

        fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            *self.last_ntp_discipline_enabled.borrow_mut() = Some(true);
            Ok(())
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            *self.last_ntp_discipline_enabled.borrow_mut() = Some(false);
            Ok(())
        }

        fn ntp_algorithm_update(
            &self,
            offset: NtpDuration,
            poll_interval: PollInterval,
        ) -> Result<(), Self::Error> {
            *self.last_offset.borrow_mut() = Some(offset);
            *self.last_poll_interval.borrow_mut() = Some(poll_interval);
            Ok(())
        }

        fn error_estimate_update(
            &self,
            est_error: NtpDuration,
            max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            *self.last_est_error.borrow_mut() = Some(est_error);
            *self.last_max_error.borrow_mut() = Some(max_error);
            Ok(())
        }

        fn status_update(&self, leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            *self.last_leap_status.borrow_mut() = Some(leap_status);
            Ok(())
        }
    }

    #[test]
    fn test_value_passthrough() {
        let base = NtpInstant::now();

        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        let ref_interval = controller.preferred_poll_interval;

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_fixed_int(0),
                NtpDuration::from_fixed_int(20),
                NtpDuration::from_fixed_int(10),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert_eq!(
            Some(NtpDuration::from_fixed_int(20)),
            *controller.clock.last_max_error.borrow()
        );
        assert_eq!(
            Some(NtpLeapIndicator::NoWarning),
            *controller.clock.last_leap_status.borrow()
        );
        assert_eq!(
            Some(ref_interval),
            *controller.clock.last_poll_interval.borrow()
        );

        controller.preferred_poll_interval = controller
            .preferred_poll_interval
            .inc(PollIntervalLimits::default());
        let ref_interval = controller.preferred_poll_interval;

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_fixed_int(0),
                NtpDuration::from_fixed_int(40),
                NtpDuration::from_fixed_int(60),
                NtpLeapIndicator::Leap59,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert_eq!(
            Some(NtpDuration::from_fixed_int(80)),
            *controller.clock.last_max_error.borrow()
        );
        assert_eq!(
            Some(NtpLeapIndicator::Leap59),
            *controller.clock.last_leap_status.borrow()
        );
        assert_eq!(
            Some(ref_interval),
            *controller.clock.last_poll_interval.borrow()
        );
    }

    #[test]
    fn test_startup_logic() {
        let system = TimeSnapshot::default();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let mut controller = ClockController::new(TestClock::default(), &system, &config);
        let base = controller.last_update_time;

        assert_eq!(*controller.clock.last_freq.borrow(), Some(0.));
        assert_eq!(
            *controller.clock.last_ntp_discipline_enabled.borrow(),
            Some(true)
        );

        controller.update(
            &config,
            &algo_config,
            &system,
            NtpDuration::from_fixed_int(0),
            NtpDuration::from_seconds(0.01),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(1),
        );

        assert_eq!(controller.state, ClockState::MeasureFreq);
        assert_eq!(
            *controller.clock.last_offset.borrow(),
            Some(NtpDuration::from_fixed_int(0))
        );

        controller.update(
            &config,
            &algo_config,
            &system,
            NtpDuration::from_fixed_int(1 << 32),
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(1801),
        );

        assert_eq!(controller.state, ClockState::Sync);
        assert_eq!(
            *controller.clock.last_offset.borrow(),
            Some(NtpDuration::from_fixed_int(1 << 32))
        );
        assert_eq!(*controller.clock.last_freq.borrow(), Some(1. / 1800.));
    }

    #[test]
    fn test_startup_logic_freq() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::StartupFreq,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        controller.update(
            &config,
            &algo_config,
            &system,
            NtpDuration::from_fixed_int(0),
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(1),
        );

        assert_eq!(controller.state, ClockState::Sync);
        assert_eq!(
            *controller.clock.last_offset.borrow(),
            Some(NtpDuration::from_fixed_int(0))
        );
    }

    #[test]
    fn test_spike_rejection() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        controller.update(
            &config,
            &algo_config,
            &system,
            2 * NtpDuration::STEP_THRESHOLD,
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(1),
        );

        assert_eq!(controller.state, ClockState::Spike);
        assert_eq!(*controller.clock.last_offset.borrow(), None);

        controller.update(
            &config,
            &algo_config,
            &system,
            NtpDuration::from_fixed_int(0),
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(2),
        );

        assert_eq!(controller.state, ClockState::Sync);
        assert_eq!(
            *controller.clock.last_offset.borrow(),
            Some(NtpDuration::from_fixed_int(0))
        );
    }

    #[test]
    fn test_spike_acceptance_over_time() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        controller.update(
            &config,
            &algo_config,
            &system,
            2 * NtpDuration::STEP_THRESHOLD,
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(1),
        );

        assert_eq!(controller.state, ClockState::Spike);
        assert_eq!(*controller.clock.last_offset.borrow(), None);

        controller.update(
            &config,
            &algo_config,
            &system,
            2 * NtpDuration::STEP_THRESHOLD,
            NtpDuration::from_seconds(0.02),
            NtpDuration::from_seconds(0.03),
            NtpLeapIndicator::NoWarning,
            base + Duration::from_secs(902),
        );

        assert_eq!(controller.state, ClockState::Sync);
        assert_eq!(
            *controller.clock.last_offset.borrow(),
            Some(2 * NtpDuration::STEP_THRESHOLD)
        );
    }

    #[test]
    fn test_accumulated_excess_detection() {
        let base = NtpInstant::now();
        let config = SystemConfig {
            accumulated_threshold: Some(NtpDuration::from_seconds(100.0)),
            ..Default::default()
        };
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::ZERO,
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(80.),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1)
            ),
            ClockUpdateResult::Ignore
        );
        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(80.),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1000),
            ),
            ClockUpdateResult::Step
        );
        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(80.),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1001)
            ),
            ClockUpdateResult::Panic
        );
    }

    #[test]
    fn test_jitter_calc() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert!(controller.jitter.to_seconds() >= 0.0095);

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );
        assert!(controller.jitter().to_seconds() < 0.006);
    }

    #[test]
    fn test_poll_preference_update() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_seconds(2e-3),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(2e-3),
                NtpDuration::from_seconds(2e-4),
                NtpDuration::from_seconds(3e-4),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );
        assert!(controller.poll_interval_counter < 0);

        controller.jitter = system.precision;
        controller.offset = NtpDuration::from_seconds(-2e-3);
        controller.poll_interval_counter = 0;
        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(-2e-3),
                NtpDuration::from_seconds(2e-4),
                NtpDuration::from_seconds(3e-4),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );
        assert!(controller.poll_interval_counter < 0);

        controller.jitter = NtpDuration::from_seconds(2e-3);
        controller.offset = NtpDuration::from_seconds(2e-3);
        controller.poll_interval_counter = 0;
        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(2e-3),
                NtpDuration::from_seconds(2e-4),
                NtpDuration::from_seconds(3e-4),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );
        assert!(controller.poll_interval_counter > 0);

        controller.jitter = NtpDuration::from_seconds(2e-3);
        controller.offset = NtpDuration::from_seconds(-2e-3);
        controller.poll_interval_counter = 0;
        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                NtpDuration::from_seconds(-2e-3),
                NtpDuration::from_seconds(2e-4),
                NtpDuration::from_seconds(3e-4),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Slew
        );
        assert!(controller.poll_interval_counter > 0);
    }

    #[test]
    fn test_excess_detection() {
        let base = NtpInstant::now();
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig::default();
        let system = TimeSnapshot::default();

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Sync,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                -2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Spike,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::Spike,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                -2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::MeasureFreq,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::MeasureFreq,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                -2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Panic
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::StartupBlank,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Step
        );

        let mut controller = ClockController {
            clock: TestClock::default(),
            state: ClockState::StartupFreq,
            last_update_time: base,
            preferred_poll_interval: PollIntervalLimits::default().min,
            poll_interval_counter: 0,
            offset: NtpDuration::from_fixed_int(0),
            jitter: system.precision,
            accumulated_steps: NtpDuration::ZERO,
        };

        assert_eq!(
            controller.update(
                &config,
                &algo_config,
                &system,
                2 * config.panic_threshold.forward.unwrap(),
                NtpDuration::from_seconds(0.02),
                NtpDuration::from_seconds(0.03),
                NtpLeapIndicator::NoWarning,
                base + Duration::from_secs(1),
            ),
            ClockUpdateResult::Step
        );
    }
}
