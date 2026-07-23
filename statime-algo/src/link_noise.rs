use crate::{
    ClockId, LinkNoiseError::NotEnoughMeasurements, link_noise::LinkNoiseError::InvalidClocks, ringbuffer::UnorderedRingBuffer,
};

const DELAYS: usize = 8;
const MIN_DELAYS_FOR_ESTIMATES: usize = 4;
/// FIXME: Consider whether we want this configurable.
const MAX_TIME_BETWEEN_HALVES: f64 = 0.5;

type Timestamp = f64;

#[derive(Debug, Copy, Clone, PartialEq)]
struct PreviousMeasurement {
    time: Timestamp,
    offset: f64,
    from: ClockId,
    to: ClockId,
}

/// An error that occured during link noise estimation
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum LinkNoiseError {
    /// One of the provided clocks is not a clock on this link.
    InvalidClocks,
    /// Both clocks in the link or in the measurement are the same.
    ClocksEqual,
    /// There are insufficient measurements to provide estimates.
    NotEnoughMeasurements,
}

/// Estimator for the noise induced by a given link
#[derive(Debug, Clone)]
pub struct LinkNoiseEstimator {
    a: ClockId,
    b: ClockId,
    roundtrip_delays: UnorderedRingBuffer,
    prev_measurement: Option<PreviousMeasurement>,
}

impl LinkNoiseEstimator {
    /// Create a new estimator for the noise on a link between clocks A and B.
    pub fn new(a: ClockId, b: ClockId) -> Result<Self, LinkNoiseError> {
        if a == b {
            Err(LinkNoiseError::ClocksEqual)
        } else {
            Ok(LinkNoiseEstimator {
                a,
                b,
                roundtrip_delays: UnorderedRingBuffer::default(),
                prev_measurement: None,
            })
        }
    }

    /// Use a measurement on the link to update our estimates for the noise on the link.
    pub fn measurement(
        mut self,
        from: ClockId,
        to: ClockId,
        offset: f64,
        time: Timestamp,
    ) -> Result<LinkNoiseEstimator, LinkNoiseError> {
        if (from != self.a && from != self.b) || (to != self.a && to != self.b) {
            return Err(LinkNoiseError::InvalidClocks);
        }

        if from == to {
            return Err(LinkNoiseError::ClocksEqual);
        }

        if let Some(prev_measurement) = self.prev_measurement.take()
            && prev_measurement.from == to
            && prev_measurement.to == from
            && time - prev_measurement.time < MAX_TIME_BETWEEN_HALVES
        {
            self.roundtrip_delays
                .insert(prev_measurement.offset + offset);
        } else {
            self.prev_measurement = Some(PreviousMeasurement {
                time,
                offset,
                from,
                to,
            })
        }

        Ok(self)
    }

    /// The current estimate of the noise on the link
    ///
    /// Errors:
    /// The noise estimate is only available if sufficient measurements have
    /// occured for a reliable estimate to be made.
    pub fn noise_estimate(&self) -> Result<f64, LinkNoiseError> {
        let roundtrip_delays = self.roundtrip_delays.as_ref();
        if roundtrip_delays.len() < MIN_DELAYS_FOR_ESTIMATES {
            return Err(LinkNoiseError::NotEnoughMeasurements);
        }
        let mean = roundtrip_delays.iter().sum::<f64>() / (roundtrip_delays.len() as f64);

        let variance = roundtrip_delays
            .iter()
            .map(|f| (f - mean).powi(2))
            .sum::<f64>()
            / ((roundtrip_delays.len() - 1) as f64);

        Ok((variance / 2.0).sqrt())
    }

    /// The current estimate of the delay on the link
    ///
    /// Errors:
    /// The delay estimate is only available if sufficient measurements have
    /// occured for a reliable estimate to be made.
    pub fn delay_estimate(&self) -> Result<f64, LinkNoiseError> {
        let roundtrip_delays = self.roundtrip_delays.as_ref();
        if roundtrip_delays.len() < MIN_DELAYS_FOR_ESTIMATES {
            return Err(LinkNoiseError::NotEnoughMeasurements);
        }

        Ok(roundtrip_delays.iter().sum::<f64>() / ((2 * roundtrip_delays.len()) as f64))
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClockId, estimator::UncertainValue, link_noise::LinkNoiseEstimator};

    #[test]
    fn link_noise_measures_link_noise_1() {
        let state = LinkNoiseEstimator::new(ClockId(1), ClockId(2))
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap();

        assert_eq!(state.noise_estimate().unwrap(), 0.0);
        assert_eq!(state.delay_estimate().unwrap(), 1.0);
    }

    #[test]
    fn link_noise_measures_link_noise_2() {
        let state = LinkNoiseEstimator::new(ClockId(1), ClockId(2))
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 1.0, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 0.5, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 0.5, 0.0)
            .unwrap()
            .measurement(ClockId(1), ClockId(2), 0.5, 0.0)
            .unwrap()
            .measurement(ClockId(2), ClockId(1), 0.5, 0.0)
            .unwrap();

        assert_almost_eq!(state.noise_estimate().unwrap(), 1.0 / (6.0f64.sqrt()));
        assert_eq!(state.delay_estimate().unwrap(), 0.75);
    }

    /// Returns a link noise estimator with 0 link noise.
    #[test]
    fn link_noise_measures_link_noise_3() {
        let a = ClockId(1);
        let b = ClockId(2);
        let delay: UncertainValue = (1.5, 0.1).into();

        let state = LinkNoiseEstimator::new(a, b)
            .unwrap()
            .measurement(a, b, delay.value, 0.0)
            .unwrap()
            .measurement(b, a, delay.value, 0.0)
            .unwrap()
            .measurement(a, b, delay.value + delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(b, a, delay.value + delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(a, b, delay.value + delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(b, a, delay.value + delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(a, b, delay.value - delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(b, a, delay.value - delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(a, b, delay.value - delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap()
            .measurement(b, a, delay.value - delay.uncertainty / 2.0f64.sqrt(), 0.0)
            .unwrap();

        assert_almost_eq!(state.delay_estimate().unwrap(), delay.value);
        assert_almost_eq!(state.noise_estimate().unwrap(), delay.uncertainty);
    }
}
