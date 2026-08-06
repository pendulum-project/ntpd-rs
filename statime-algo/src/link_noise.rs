use statime_base::{ClockId, Direction, Duration, LinkId, TAI, Timestamp};

#[cfg(not(feature = "std"))]
use crate::float_polyfill::FloatPolyfill;
use crate::{AlgoError, ringbuffer::UnorderedRingBuffer};

const MIN_DELAYS_FOR_ESTIMATES: usize = 4;
/// FIXME: Consider whether we want this configurable.
const MAX_TIME_BETWEEN_HALVES: Duration = Duration::from_seconds_nanos(0, 500_000_000);

#[derive(Debug, Copy, Clone, PartialEq)]
struct PreviousMeasurement {
    time: Timestamp<TAI>,
    offset: f64,
    direction: Direction,
}

/// A struct containing the delay and noise estimates for a link.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct LinkDelayNoiseEstimate {
    pub delay: f64,
    pub noise: f64,
}

/// Estimator for the noise induced by a given link
#[derive(Debug, Clone)]
pub struct LinkNoiseEstimator {
    pub(crate) id: LinkId,
    roundtrip_delays: UnorderedRingBuffer,
    prev_measurement: Option<PreviousMeasurement>,
}

impl LinkNoiseEstimator {
    /// Create a new estimator for the noise on a link.
    pub fn new(id: LinkId) -> Self {
        LinkNoiseEstimator {
            id,
            roundtrip_delays: UnorderedRingBuffer::default(),
            prev_measurement: None,
        }
    }

    /// Use a measurement on the link to update our estimates for the noise on the link.
    pub fn measurement(
        mut self,
        direction: Direction,
        offset: f64,
        time: Timestamp<TAI>,
    ) -> LinkNoiseEstimator {
        if let Some(prev_measurement) = self.prev_measurement.take()
            && prev_measurement.direction.is_reverse_of(direction)
            && time - prev_measurement.time < MAX_TIME_BETWEEN_HALVES
        {
            self.roundtrip_delays
                .insert(prev_measurement.offset + offset);
        } else {
            self.prev_measurement = Some(PreviousMeasurement {
                time,
                offset,
                direction,
            });
        }

        self
    }

    /// Absorb the results of a clock phase jump
    #[must_use]
    pub fn absorb_offset_change(mut self, steered_clock: ClockId) -> LinkNoiseEstimator {
        if self.id.first_clock() == steered_clock || self.id.second_clock() == steered_clock {
            // One of the clocks in this link has a discontinuity, which makes a delay
            // estimate accross that invalid, so ignore any previous measurements.
            self.prev_measurement = None;
        }
        self
    }

    /// Absorb the results of a system clock phase jump
    #[must_use]
    pub fn absorb_system_clock_offset_change(
        mut self,
        steered_clock: ClockId,
        offset_change: Duration,
    ) -> LinkNoiseEstimator {
        if self.id.first_clock() == steered_clock || self.id.second_clock() == steered_clock {
            // One of the clocks in this link has a discontinuity, which makes a delay
            // estimate accross that invalid, so ignore any previous measurements.
            self.prev_measurement = None;
        } else if let Some(measurement) = &mut self.prev_measurement {
            // The clocks on this link don't have any discontinuities, however the
            // time at which the measurements have been taken has changed meaning.
            // We correct for that by putting the time of the previous measurement
            // in the frame "as if" the offset discontinuity in the system clock
            // happened before the first measurement.
            measurement.time += offset_change;
        }
        self
    }

    /// The current estimate of the noise on the link
    ///
    /// # Errors
    /// The noise estimate is only available if sufficient measurements have
    /// occured for a reliable estimate to be made.
    pub fn noise_estimate(&self) -> Result<f64, AlgoError> {
        let roundtrip_delays = self.roundtrip_delays.as_ref();
        if roundtrip_delays.len() < MIN_DELAYS_FOR_ESTIMATES {
            return Err(AlgoError::NotEnoughMeasurements(self.id));
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "roundtrip_delays.len() is at most 8, which will fit, therefore the warning is spurious"
        )]
        let mean = roundtrip_delays.iter().sum::<f64>() / (roundtrip_delays.len() as f64);

        #[expect(
            clippy::cast_precision_loss,
            reason = "roundtrip_delays.len()-1 is at most 7, which will fit, therefore the warning is spurious"
        )]
        let variance = roundtrip_delays
            .iter()
            .map(|f| (f - mean).powi(2))
            .sum::<f64>()
            / ((roundtrip_delays.len() - 1) as f64);

        Ok((variance / 2.0).sqrt())
    }

    /// The current estimate of the delay on the link
    ///
    /// # Errors
    /// The delay estimate is only available if sufficient measurements have
    /// occured for a reliable estimate to be made.
    pub fn delay_estimate(&self) -> Result<f64, AlgoError> {
        let roundtrip_delays = self.roundtrip_delays.as_ref();
        if roundtrip_delays.len() < MIN_DELAYS_FOR_ESTIMATES {
            return Err(AlgoError::NotEnoughMeasurements(self.id));
        }

        #[expect(
            clippy::cast_precision_loss,
            reason = "2*roundtrip_delays.len() is at most 16, which will fit, therefore the warning is spurious"
        )]
        Ok(roundtrip_delays.iter().sum::<f64>() / ((2 * roundtrip_delays.len()) as f64))
    }

    /// The current estimate of the delay and noise on the link
    ///
    /// # Errors
    /// The delay and noise estimates are only available if sufficient
    /// measurements have occured for a reliable estimate to be made.
    pub fn delay_and_noise_estimate(&self) -> Result<LinkDelayNoiseEstimate, AlgoError> {
        Ok(LinkDelayNoiseEstimate {
            delay: self.delay_estimate()?,
            noise: self.noise_estimate()?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp, reason = "Test code")]
#[allow(clippy::too_many_lines, reason = "Test code")]
mod tests {
    use statime_base::{ClockId, Direction, Duration, LinkId, Timestamp};

    use crate::{AlgoError, estimator::UncertainValue, link_noise::LinkNoiseEstimator};

    #[test]
    fn link_noise_measures_link_noise_1() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH);

        assert_eq!(state.noise_estimate().unwrap(), 0.0);
        assert_eq!(state.delay_estimate().unwrap(), 1.0);
    }

    #[test]
    fn link_noise_measures_link_noise_2() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 0.5, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 0.5, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Forward, 0.5, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, 0.5, Timestamp::UNIX_EPOCH);

        assert_almost_eq!(state.noise_estimate().unwrap(), 1.0 / (6.0f64.sqrt()));
        assert_eq!(state.delay_estimate().unwrap(), 0.75);
    }

    /// Returns a link noise estimator with 0 link noise.
    #[test]
    fn link_noise_measures_link_noise_3() {
        let a = ClockId::new();
        let b = ClockId::new();
        let link = LinkId::new(a, b).unwrap();
        let delay: UncertainValue = (1.5, 0.1).into();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, delay.value, Timestamp::UNIX_EPOCH)
            .measurement(Direction::Reverse, delay.value, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Forward,
                delay.value + delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Reverse,
                delay.value + delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Forward,
                delay.value + delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Reverse,
                delay.value + delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Forward,
                delay.value - delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Reverse,
                delay.value - delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Forward,
                delay.value - delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            )
            .measurement(
                Direction::Reverse,
                delay.value - delay.uncertainty / 2.0f64.sqrt(),
                Timestamp::UNIX_EPOCH,
            );

        assert_almost_eq!(state.delay_estimate().unwrap(), delay.value);
        assert_almost_eq!(state.noise_estimate().unwrap(), delay.uncertainty);
    }

    #[test]
    fn link_noise_accept_samples_within_bounds() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 400_000_000),
            );

        assert_almost_eq!(state.noise_estimate().unwrap(), 1.0 / (6.0f64.sqrt()));
        assert_eq!(state.delay_estimate().unwrap(), 0.75);
    }

    #[test]
    fn link_noise_rejects_samples_too_far_appart() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 600_000_000),
            );

        assert_eq!(
            state.noise_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
        assert_eq!(
            state.delay_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
    }

    #[test]
    fn link_noise_measurement_during_steer() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let clock_3 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_offset_change(clock_1)
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 400_000_000),
            );

        assert_eq!(
            state.noise_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
        assert_eq!(
            state.delay_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_offset_change(clock_2)
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 400_000_000),
            );

        assert_eq!(
            state.noise_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
        assert_eq!(
            state.delay_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_offset_change(clock_3)
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 400_000_000),
            );

        assert_almost_eq!(state.noise_estimate().unwrap(), 1.0 / (6.0f64.sqrt()));
        assert_eq!(state.delay_estimate().unwrap(), 0.75);
    }

    #[test]
    fn link_noise_measurement_during_sysclock_steer() {
        let clock_1 = ClockId::new();
        let clock_2 = ClockId::new();
        let clock_3 = ClockId::new();
        let link = LinkId::new(clock_1, clock_2).unwrap();

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_system_clock_offset_change(clock_1, Duration::from_seconds_nanos(1, 0))
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(31, 400_000_000),
            );

        assert_eq!(
            state.noise_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
        assert_eq!(
            state.delay_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_system_clock_offset_change(clock_2, Duration::from_seconds_nanos(1, 0))
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(31, 400_000_000),
            );

        assert_eq!(
            state.noise_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );
        assert_eq!(
            state.delay_estimate().unwrap_err(),
            AlgoError::NotEnoughMeasurements(link)
        );

        let state = LinkNoiseEstimator::new(link)
            .measurement(Direction::Forward, 1.0, Timestamp::UNIX_EPOCH)
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(0, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 0),
            )
            .measurement(
                Direction::Reverse,
                1.0,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(10, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 0),
            )
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(20, 400_000_000),
            )
            .measurement(
                Direction::Forward,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(30, 0),
            )
            .absorb_system_clock_offset_change(clock_3, Duration::from_seconds_nanos(1, 0))
            .measurement(
                Direction::Reverse,
                0.5,
                Timestamp::UNIX_EPOCH + Duration::from_seconds_nanos(31, 400_000_000),
            );

        assert_almost_eq!(state.noise_estimate().unwrap(), 1.0 / (6.0f64.sqrt()));
        assert_eq!(state.delay_estimate().unwrap(), 0.75);
    }
}
