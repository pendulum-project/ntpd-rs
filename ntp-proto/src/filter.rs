// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::{packet::NtpLeapIndicator, NtpDuration, NtpTimestamp};

/// frequency tolerance (15 ppm)
// const PHI: f64 = 15e-6;
fn multiply_by_phi(duration: NtpDuration) -> NtpDuration {
    (duration * 15) / 1_000_000
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpTimestamp,
}

impl FilterTuple {
    const DUMMY: Self = Self {
        offset: NtpDuration::ZERO,
        delay: NtpDuration::MAX_DISPERSION,
        dispersion: NtpDuration::MAX_DISPERSION,
        time: NtpTimestamp::ZERO,
    };

    fn is_dummy(self) -> bool {
        self == Self::DUMMY
    }
}

#[derive(Debug, Clone)]
pub struct ClockFilterContents {
    register: [FilterTuple; 8],
}

impl ClockFilterContents {
    #[allow(dead_code)]
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
    }

    /// Insert the new tuple at index 0, move all other tuples one to the right.
    /// The final (oldest) tuple is discarded
    fn shift_and_insert(&mut self, mut current: FilterTuple, dispersion_correction: NtpDuration) {
        for tuple in self.register.iter_mut() {
            tuple.dispersion += dispersion_correction;

            std::mem::swap(&mut current, tuple);
        }
    }
}

/// Temporary list
#[derive(Debug, Clone)]
struct TemporaryList {
    /// Invariant: this array is always sorted by increasing delay!
    register: [FilterTuple; 8],
}

impl TemporaryList {
    fn from_clock_filter_contents(source: &ClockFilterContents) -> Self {
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
    fn jitter(&self, smallest_delay: FilterTuple, system_precision: f64) -> f64 {
        Self::jitter_help(self.valid_tuples(), smallest_delay, system_precision)
    }

    fn jitter_help(
        valid_tuples: &[FilterTuple],
        smallest_delay: FilterTuple,
        system_precision: f64,
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
        jitter.max(system_precision)
    }

    #[cfg(test)]
    const fn new() -> Self {
        Self {
            register: [FilterTuple::DUMMY; 8],
        }
    }
}

pub struct System {
    precision: f64,
    poll: NtpDuration,
    leap_indicator: NtpLeapIndicator,
}

impl System {
    #[cfg(test)]
    fn dummy() -> Self {
        Self {
            precision: 0.0,
            poll: NtpDuration::default(),
            leap_indicator: NtpLeapIndicator::NoWarning,
        }
    }
}

pub struct Peer {
    clock_filter: ClockFilterContents,
    t: NtpTimestamp,

    jitter: f64,
    dispersion: NtpDuration,

    offset: NtpDuration,
    delay: NtpDuration,

    burst_counter: u32,
}

pub struct LocalClock {
    t: NtpTimestamp,
}

pub struct PeerProcessStatistics {
    pub offset: NtpDuration,
    pub delay: NtpDuration,

    pub dispersion: NtpDuration,
    pub jitter: f64,

    pub filter: ClockFilterContents,
    pub filter_time: NtpTimestamp,
}

#[allow(dead_code)]
pub fn clock_filter(
    peer_time: NtpTimestamp,
    system_precision: f64,
    leap_indicator: NtpLeapIndicator,
    mut clock_filter: ClockFilterContents,
    new_tuple: FilterTuple,
) -> Option<PeerProcessStatistics> {
    //    let new_tuple = FilterTuple {
    //        offset: clock_offset,
    //        delay: roundtrip_delay,
    //        dispersion,
    //        time: local_clock_time,
    //    };

    let dispersion_correction = multiply_by_phi(new_tuple.time - peer_time);
    clock_filter.shift_and_insert(new_tuple, dispersion_correction);

    let temporary_list = TemporaryList::from_clock_filter_contents(&clock_filter);
    let smallest_delay = *temporary_list.smallest_delay();

    // Prime directive: use a sample only once and never a sample
    // older than the latest one, but anything goes before first
    // synchronized.
    if smallest_delay.time - peer_time <= NtpDuration::ZERO && leap_indicator.is_synchronized() {
        return None;
    }

    let offset = smallest_delay.offset;
    let delay = smallest_delay.delay;

    let dispersion = temporary_list.dispersion();
    let jitter = temporary_list.jitter(smallest_delay, system_precision);

    let statistics = PeerProcessStatistics {
        offset,
        delay,
        dispersion,
        jitter,
        filter: clock_filter,
        filter_time: smallest_delay.time,
    };

    Some(statistics)
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
        let mut register = ClockFilterContents::new();
        register.register[0].offset = NtpDuration::from_seconds(42.0);
        let first = register.register[0];
        let system = System::dummy();
        let value = TemporaryList::from_clock_filter_contents(&register).jitter(&system, first);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = TemporaryList::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(30.0);
        let first = register.register[0];
        let system = System::dummy();
        let value = register.jitter(&system, first);

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
        let system = System::dummy();
        let value = register.jitter(&system, first);

        // jitter is calculated relative to the first tuple
        assert!((value - 5.0).abs() < 1e-6)
    }
}
