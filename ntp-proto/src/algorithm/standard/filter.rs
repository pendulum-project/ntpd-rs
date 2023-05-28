// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::peer::Measurement;
use crate::time_types::{FrequencyTolerance, NtpInstant};
use crate::{packet::NtpLeapIndicator, NtpDuration};
use tracing::{debug, instrument, warn};

use super::peer::PeerStatistics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpInstant,
}

impl FilterTuple {
    const fn dummy(time: NtpInstant) -> Self {
        Self {
            offset: NtpDuration::ZERO,
            delay: NtpDuration::MAX_DISPERSION,
            dispersion: NtpDuration::MAX_DISPERSION,
            time,
        }
    }

    fn is_dummy(self) -> bool {
        self.offset == NtpDuration::ZERO
            && self.delay == NtpDuration::MAX_DISPERSION
            && self.dispersion == NtpDuration::MAX_DISPERSION
    }

    /// The default logic for updating a peer with a new packet.
    ///
    /// A Broadcast association requires different logic.
    /// All other associations should use this function
    pub fn from_measurement(
        measurement: Measurement,
        system_precision: NtpDuration,
        frequency_tolerance: FrequencyTolerance,
    ) -> Self {
        let packet_precision = NtpDuration::from_exponent(measurement.precision);

        let dispersion = packet_precision
            + system_precision
            + ((measurement.delay
                + (measurement.transmit_timestamp - measurement.receive_timestamp))
                * frequency_tolerance);

        Self {
            delay: measurement.delay,
            offset: measurement.offset,
            dispersion,
            time: measurement.monotime,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct LastMeasurements {
    register: [FilterTuple; 8],
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    stratum: u8,
    leap: NtpLeapIndicator,
}

impl LastMeasurements {
    pub const fn new(instant: NtpInstant) -> Self {
        Self {
            register: [FilterTuple::dummy(instant); 8],
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            stratum: 0,
            leap: NtpLeapIndicator::Unknown,
        }
    }

    pub fn last_root_delay(&self) -> NtpDuration {
        self.root_delay
    }

    pub fn last_root_dispersion(&self) -> NtpDuration {
        self.root_dispersion
    }

    #[cfg(test)]
    pub fn set_root_delay(&mut self, root_delay: NtpDuration) {
        self.root_delay = root_delay;
    }

    #[cfg(test)]
    pub fn set_root_dispersion(&mut self, root_dispersion: NtpDuration) {
        self.root_dispersion = root_dispersion;
    }

    #[cfg(test)]
    pub fn set_leap(&mut self, leap: NtpLeapIndicator) {
        self.leap = leap
    }

    pub fn last_stratum(&self) -> u8 {
        self.stratum
    }

    pub fn last_leap(&self) -> NtpLeapIndicator {
        self.leap
    }

    /// Insert the new tuple at index 0, move all other tuples one to the right.
    /// The final (oldest) tuple is discarded
    fn shift_and_insert(&mut self, mut current: FilterTuple, dispersion_correction: NtpDuration) {
        for tuple in self.register.iter_mut() {
            // adding the dispersion correction would make the dummy no longer a dummy
            if !tuple.is_dummy() {
                tuple.dispersion += dispersion_correction;
            }

            std::mem::swap(&mut current, tuple);
        }
    }

    #[instrument(level = "trace")]
    pub fn step(
        &mut self,
        measurement: Measurement,
        peer_time: NtpInstant,
        system_leap_indicator: NtpLeapIndicator,
        system_precision: NtpDuration,
        frequency_tolerance: FrequencyTolerance,
    ) -> Option<(PeerStatistics, NtpInstant)> {
        let new_tuple =
            FilterTuple::from_measurement(measurement, system_precision, frequency_tolerance);

        // always update root delay and root dispersion
        self.root_delay = measurement.root_delay;
        self.root_dispersion = measurement.root_dispersion;
        self.stratum = measurement.stratum;
        self.leap = measurement.leap;

        // correction depends on time passed since last register update!, not peer_time
        let dispersion_correction =
            NtpInstant::abs_diff(new_tuple.time, self.register[0].time) * frequency_tolerance;
        self.shift_and_insert(new_tuple, dispersion_correction);

        let temporary_list = TemporaryList::from_clock_filter_contents(self);
        let smallest_delay = *temporary_list.smallest_delay();

        // Prime directive: use a sample only once and never a sample
        // older than the latest one, but anything goes before first
        // synchronized.
        if smallest_delay.time <= peer_time && system_leap_indicator.is_synchronized() {
            debug!(
                peer_time = debug(peer_time),
                smallest_delay_time = debug(smallest_delay.time),
                latest_time = debug(new_tuple.time),
                "Last packet is not (yet) best packet"
            );
            return None;
        }

        let offset = smallest_delay.offset;
        let delay = smallest_delay.delay;

        let dispersion = temporary_list.dispersion();
        let jitter = temporary_list.jitter(smallest_delay, system_precision);

        let statistics = PeerStatistics {
            offset,
            delay,
            dispersion,
            jitter,
        };

        debug!(
            statistics = debug(statistics),
            time = debug(smallest_delay.time),
            "Peer statistics updated"
        );
        Some((statistics, smallest_delay.time))
    }
}

/// Temporary list
#[derive(Debug, Clone)]
struct TemporaryList {
    /// Invariant: this array is always sorted by increasing delay!
    register: [FilterTuple; 8],
}

impl TemporaryList {
    fn from_clock_filter_contents(source: &LastMeasurements) -> Self {
        // copy the registers
        let mut register = source.register;

        // sort by delay, ignoring NaN
        register.sort_by(|t1, t2| {
            t1.delay
                .partial_cmp(&t2.delay)
                .unwrap_or(std::cmp::Ordering::Less)
        });

        Self { register }
    }

    fn smallest_delay(&self) -> &FilterTuple {
        &self.register[0]
    }

    /// Prefix of the temporary list containing only the valid tuples
    fn valid_tuples(&self) -> &[FilterTuple] {
        let num_invalid_tuples = self
            .register
            .iter()
            .rev()
            .take_while(|t| t.is_dummy())
            .count();

        let num_valid_tuples = self.register.len() - num_invalid_tuples;

        &self.register[..num_valid_tuples]
    }

    /// #[no_run]
    ///                     i=n-1
    ///                     ---     epsilon_i
    ///      epsilon =       \     ----------
    ///                      /        (i+1)
    ///                     ---     2
    ///                     i=0
    /// Invariant: the register is sorted wrt delay
    fn dispersion(&self) -> NtpDuration {
        self.register
            .iter()
            .enumerate()
            .map(|(i, t)| t.dispersion / 2i64.pow(i as u32 + 1))
            .fold(NtpDuration::default(), |a, b| a + b)
    }

    /// #[no_run]
    ///                          +-----                 -----+^1/2
    ///                          |  n-1                      |
    ///                          |  ---                      |
    ///                  1       |  \                     2  |
    ///      psi   =  -------- * |  /    (theta_0-theta_j)   |
    ///                (n-1)     |  ---                      |
    ///                          |  j=1                      |
    ///                          +-----                 -----+
    ///
    /// Invariant: the register is sorted wrt delay
    fn jitter(&self, smallest_delay: FilterTuple, system_precision: NtpDuration) -> f64 {
        Self::jitter_help(self.valid_tuples(), smallest_delay, system_precision)
    }

    fn jitter_help(
        valid_tuples: &[FilterTuple],
        smallest_delay: FilterTuple,
        system_precision: NtpDuration,
    ) -> f64 {
        let root_mean_square = valid_tuples
            .iter()
            .map(|t| (t.offset - smallest_delay.offset).to_seconds().powi(2))
            .sum::<f64>()
            .sqrt();

        // root mean square average (RMS average). - 1 to exclude the smallest_delay
        let jitter = root_mean_square / (valid_tuples.len() - 1) as f64;

        // In order to ensure consistency and avoid divide exceptions in other
        // computations, the psi is bounded from below by the system precision
        // s.rho expressed in seconds.
        f64::max(jitter, system_precision.to_seconds())
    }

    #[cfg(test)]
    const fn new(instant: NtpInstant) -> Self {
        Self {
            register: [FilterTuple::dummy(instant); 8],
        }
    }
}

#[cfg(test)]
mod test {
    use crate::NtpTimestamp;

    use super::*;

    #[test]
    fn dispersion_of_dummys() {
        // The observer should note (a) if all stages contain the dummy tuple
        // with dispersion MAXDISP, the computed dispersion is a little less than 16 s

        let register = TemporaryList::new(NtpInstant::now());
        let value = register.dispersion().to_seconds();

        assert!((16.0 - value) < 0.1)
    }

    #[test]
    fn dummys_are_not_valid() {
        let instant = NtpInstant::now();
        assert!(TemporaryList::new(instant).valid_tuples().is_empty())
    }

    #[test]
    fn jitter_of_single() {
        let mut register = LastMeasurements::new(NtpInstant::now());
        register.register[0].offset = NtpDuration::from_seconds(42.0);
        let first = register.register[0];
        let value =
            TemporaryList::from_clock_filter_contents(&register).jitter(first, NtpDuration::ZERO);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = TemporaryList::new(NtpInstant::now());
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let value = register.jitter(first, NtpDuration::ZERO);

        // jitter is calculated relative to the first tuple
        assert!((value - 10.0).abs() < 1e-6)
    }

    #[test]
    fn jitter_of_triple() {
        let mut register = TemporaryList::new(NtpInstant::now());
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(20.0);
        register.register[2].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let value = register.jitter(first, NtpDuration::ZERO);

        // jitter is calculated relative to the first tuple
        assert!((value - 5.0).abs() < 1e-6)
    }

    #[test]
    fn clock_filter_defaults() {
        let instant = NtpInstant::now();

        let measurement = Measurement {
            delay: NtpDuration::ZERO,
            offset: NtpDuration::ZERO,
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: instant,

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };

        let mut measurements = LastMeasurements::new(instant);

        let peer_time = instant;
        let update = measurements.step(
            measurement,
            peer_time,
            NtpLeapIndicator::NoWarning,
            NtpDuration::ZERO,
            FrequencyTolerance::ppm(15),
        );

        // because "time" is zero, the same as all the dummy tuples,
        // the "new" tuple is not newer and hence rejected
        assert!(update.is_none());
    }

    #[test]
    fn clock_filter_new() {
        let base = NtpInstant::now();

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.05),
            offset: NtpDuration::from_seconds(0.1),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: base + std::time::Duration::new(1, 0),

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };

        let mut measurements = LastMeasurements::new(base);

        let mut peer_time = base;
        let update = measurements.step(
            measurement,
            peer_time,
            NtpLeapIndicator::NoWarning,
            NtpDuration::ZERO,
            FrequencyTolerance::ppm(15),
        );

        assert!(update.is_some());

        let (statistics, new_time) = update.unwrap();

        assert_eq!(statistics.offset, measurement.offset);
        assert_eq!(statistics.delay, measurement.delay);
        assert_eq!(new_time, measurement.monotime);

        peer_time = new_time;

        // there is just one valid sample
        assert_eq!(statistics.jitter, 0.0);

        let temporary = TemporaryList::from_clock_filter_contents(&measurements);

        assert_eq!(temporary.valid_tuples().len(), 1);

        let measurement = Measurement {
            delay: NtpDuration::from_seconds(0.04),
            offset: NtpDuration::from_seconds(0.09),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: base + std::time::Duration::new(2, 0),

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };

        let update = measurements.step(
            measurement,
            peer_time,
            NtpLeapIndicator::NoWarning,
            NtpDuration::ZERO,
            FrequencyTolerance::ppm(15),
        );

        let (statistics, new_time) = update.unwrap();
        assert_eq!(new_time, measurement.monotime);
        assert!(statistics.jitter > 0.0);
        assert!(measurements.register[1].dispersion > NtpDuration::ZERO);

        peer_time = new_time;

        let measurement = Measurement {
            offset: NtpDuration::from_seconds(0.1),
            delay: NtpDuration::from_seconds(0.06),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: base + std::time::Duration::new(3, 0),

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };

        let update = measurements.step(
            measurement,
            peer_time,
            NtpLeapIndicator::NoWarning,
            NtpDuration::ZERO,
            FrequencyTolerance::ppm(15),
        );

        assert!(update.is_none());
    }

    #[test]
    fn clock_filter_dispersion_update() {
        let base = NtpInstant::now();
        let mut filter = LastMeasurements::new(base);

        let a = Measurement {
            offset: Default::default(),
            delay: Default::default(),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: base + std::time::Duration::from_secs(1000),

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };
        let b = Measurement {
            offset: Default::default(),
            delay: Default::default(),
            transmit_timestamp: NtpTimestamp::default(),
            receive_timestamp: NtpTimestamp::default(),
            localtime: NtpTimestamp::default(),
            monotime: base + std::time::Duration::from_secs(2000),

            stratum: 0,
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap: NtpLeapIndicator::Unknown,
            precision: 0,
        };

        filter.step(
            a,
            base,
            NtpLeapIndicator::NoWarning,
            NtpDuration::from_exponent(-32),
            FrequencyTolerance::ppm(15),
        );
        let initial_dispersion = filter.register[0].dispersion.to_seconds();

        filter.step(
            b,
            base,
            NtpLeapIndicator::NoWarning,
            NtpDuration::from_exponent(-32),
            FrequencyTolerance::ppm(15),
        );

        assert!(((filter.register[1].dispersion.to_seconds() - initial_dispersion) - 15e-3) < 1e-6);
    }
}
