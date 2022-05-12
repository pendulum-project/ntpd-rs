// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::packet::NtpAssociationMode;
use crate::peer::PeerStatistics;
use crate::time_types::{FrequencyTolerance, NtpInstant};
use crate::{packet::NtpLeapIndicator, NtpDuration, NtpHeader, NtpTimestamp};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpInstant,
}

impl FilterTuple {
    const DUMMY: Self = Self {
        offset: NtpDuration::ZERO,
        delay: NtpDuration::MAX_DISPERSION,
        dispersion: NtpDuration::MAX_DISPERSION,
        time: NtpInstant::ZERO,
    };

    fn is_dummy(self) -> bool {
        self == Self::DUMMY
    }

    /// The default logic for updating a peer with a new packet.
    ///
    /// A Broadcast association requires different logic.
    /// All other associations should use this function
    pub(crate) fn from_packet_default(
        packet: &NtpHeader,
        system_precision: NtpDuration,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
        destination_timestamp: NtpTimestamp,
    ) -> Self {
        // for reference
        //
        // | org       | T1         | origin timestamp      |
        // | rec       | T2         | receive timestamp     |
        // | xmt       | T3         | transmit timestamp    |
        // | dst       | T4         | destination timestamp |

        // for a broadcast association, different logic is used
        debug_assert_ne!(packet.mode, NtpAssociationMode::Broadcast);

        let packet_precision = NtpDuration::from_exponent(packet.precision);

        // offset is the average of the deltas (T2 - T1) and (T3 - T4)
        let offset1 = packet.receive_timestamp - packet.origin_timestamp;
        let offset2 = packet.transmit_timestamp - destination_timestamp;
        let offset = (offset1 + offset2) / 2i64;

        // delay is (T4 - T1) - (T3 - T2)
        let delta1 = destination_timestamp - packet.origin_timestamp;
        let delta2 = packet.transmit_timestamp - packet.receive_timestamp;
        // In cases where the server and client clocks are running at different rates
        // and with very fast networks, the delay can appear negative.
        // delay is clamped to ensure it is always positive
        let delay = Ord::max(system_precision, delta1 - delta2);

        let dispersion = packet_precision + system_precision + (delta1 * frequency_tolerance);

        Self {
            offset,
            delay,
            dispersion,
            time: local_clock_time,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LastMeasurements {
    register: [FilterTuple; 8],
}

impl Default for LastMeasurements {
    fn default() -> Self {
        Self::new()
    }
}

impl LastMeasurements {
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
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

    pub(crate) fn step(
        &mut self,
        new_tuple: FilterTuple,
        peer_time: NtpInstant,
        system_leap_indicator: NtpLeapIndicator,
        system_precision: NtpDuration,
        frequency_tolerance: FrequencyTolerance,
    ) -> Option<(PeerStatistics, NtpInstant)> {
        let dispersion_correction = (new_tuple.time - peer_time) * frequency_tolerance;
        self.shift_and_insert(new_tuple, dispersion_correction);

        let temporary_list = TemporaryList::from_clock_filter_contents(self);
        let smallest_delay = *temporary_list.smallest_delay();

        // Prime directive: use a sample only once and never a sample
        // older than the latest one, but anything goes before first
        // synchronized.
        if smallest_delay.time <= peer_time && system_leap_indicator.is_synchronized() {
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
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
    }
}

#[cfg(feature = "fuzz")]
pub fn fuzz_tuple_from_packet_default(
    client: u64,
    client_interval: u32,
    server: u64,
    server_interval: u32,
    client_precision: i8,
    server_precision: i8,
) {
    let mut packet = NtpHeader::new();
    packet.origin_timestamp = NtpTimestamp::from_fixed_int(client);
    packet.receive_timestamp = NtpTimestamp::from_fixed_int(server);
    packet.transmit_timestamp =
        NtpTimestamp::from_fixed_int(server.wrapping_add(server_interval as u64));
    packet.precision = server_precision;

    let result = FilterTuple::from_packet_default(
        &packet,
        NtpDuration::from_exponent(client_precision),
        NtpInstant::ZERO,
        FrequencyTolerance::ppm(15),
        NtpTimestamp::from_fixed_int(client.wrapping_add(client_interval as u64)),
    );

    assert!(result.delay >= NtpDuration::from_fixed_int(0));
    assert!(result.dispersion >= NtpDuration::from_fixed_int(0));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dispersion_of_dummys() {
        // The observer should note (a) if all stages contain the dummy tuple
        // with dispersion MAXDISP, the computed dispersion is a little less than 16 s

        let register = TemporaryList::new();
        let value = register.dispersion().to_seconds();

        assert!((16.0 - value) < 0.1)
    }

    #[test]
    fn dummys_are_not_valid() {
        assert!(TemporaryList::new().valid_tuples().is_empty())
    }

    #[test]
    fn jitter_of_single() {
        let mut register = LastMeasurements::new();
        register.register[0].offset = NtpDuration::from_seconds(42.0);
        let first = register.register[0];
        let value =
            TemporaryList::from_clock_filter_contents(&register).jitter(first, NtpDuration::ZERO);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = TemporaryList::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let value = register.jitter(first, NtpDuration::ZERO);

        // jitter is calculated relative to the first tuple
        assert!((value - 10.0).abs() < 1e-6)
    }

    #[test]
    fn jitter_of_triple() {
        let mut register = TemporaryList::new();
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

        let new_tuple = FilterTuple {
            offset: Default::default(),
            delay: Default::default(),
            dispersion: Default::default(),
            time: instant,
        };

        let mut measurements = LastMeasurements::default();

        let peer_time = instant;
        let update = measurements.step(
            new_tuple,
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
        let new_tuple = FilterTuple {
            offset: NtpDuration::from_seconds(12.0),
            delay: NtpDuration::from_seconds(14.0),
            dispersion: Default::default(),
            time: NtpInstant::from_bits((1i64 << 32).to_be_bytes()),
        };

        let mut measurements = LastMeasurements::default();

        let peer_time = NtpInstant::ZERO;
        let update = measurements.step(
            new_tuple,
            peer_time,
            NtpLeapIndicator::NoWarning,
            NtpDuration::ZERO,
            FrequencyTolerance::ppm(15),
        );

        assert!(update.is_some());

        let (statistics, new_time) = update.unwrap();

        assert_eq!(statistics.offset, new_tuple.offset);
        assert_eq!(statistics.delay, new_tuple.delay);
        assert_eq!(new_time, new_tuple.time);

        // there is just one valid sample
        assert_eq!(statistics.jitter, 0.0);

        let temporary = TemporaryList::from_clock_filter_contents(&measurements);

        assert_eq!(temporary.register[0], new_tuple);
        assert_eq!(temporary.valid_tuples(), &[new_tuple]);
    }

    #[test]
    fn test_tuple_from_packet_default() {
        let mut packet = NtpHeader::new();
        packet.origin_timestamp = NtpTimestamp::from_fixed_int(0);
        packet.receive_timestamp = NtpTimestamp::from_fixed_int(1);
        packet.transmit_timestamp = NtpTimestamp::from_fixed_int(2);
        packet.precision = -32;

        let result = FilterTuple::from_packet_default(
            &packet,
            NtpDuration::from_exponent(-32),
            NtpInstant::from_fixed_int(4),
            FrequencyTolerance::ppm(15),
            NtpTimestamp::from_fixed_int(3),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(0));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(2));
        assert!(result.dispersion >= NtpDuration::from_fixed_int(0));

        packet.origin_timestamp = NtpTimestamp::from_fixed_int(0);
        packet.receive_timestamp = NtpTimestamp::from_fixed_int(2);
        packet.transmit_timestamp = NtpTimestamp::from_fixed_int(3);
        packet.precision = -32;

        let result = FilterTuple::from_packet_default(
            &packet,
            NtpDuration::from_exponent(-32),
            NtpInstant::from_fixed_int(4),
            FrequencyTolerance::ppm(15),
            NtpTimestamp::from_fixed_int(3),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(2));
        assert!(result.dispersion >= NtpDuration::from_fixed_int(0));

        packet.origin_timestamp = NtpTimestamp::from_fixed_int(0);
        packet.receive_timestamp = NtpTimestamp::from_fixed_int(0);
        packet.transmit_timestamp = NtpTimestamp::from_fixed_int(5);
        packet.precision = -32;

        let result = FilterTuple::from_packet_default(
            &packet,
            NtpDuration::from_exponent(-32),
            NtpInstant::from_fixed_int(4),
            FrequencyTolerance::ppm(15),
            NtpTimestamp::from_fixed_int(3),
        );
        assert_eq!(result.offset, NtpDuration::from_fixed_int(1));
        assert_eq!(result.delay, NtpDuration::from_fixed_int(1));
        assert!(result.dispersion >= NtpDuration::from_fixed_int(0));
    }
}
