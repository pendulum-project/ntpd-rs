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
const ONE_OVER_PHI: i64 = 15_000_000;

/// spike gate (clock filter)
const SGATE: f64 = 3.0;

#[derive(Debug, Clone, Copy, PartialEq)]
struct FilterTuple {
    offset: NtpDuration,
    delay: NtpDuration,
    dispersion: NtpDuration,
    time: NtpTimestamp,
}

impl FilterTuple {
    fn dummy() -> Self {
        Self {
            offset: NtpDuration::default(),
            delay: NtpDuration::MAXDISP,
            dispersion: NtpDuration::MAXDISP,
            time: NtpTimestamp::default(),
        }
    }

    fn is_dummy(self) -> bool {
        self == Self::dummy()
    }
}

#[derive(Debug, Clone, Copy)]
struct ClockFilterContents {
    register: [FilterTuple; 8],
}

impl ClockFilterContents {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            register: [FilterTuple::dummy(); 8],
        }
    }

    fn shift_and_insert(&mut self, new_tuple: FilterTuple, dispersion_correction: NtpDuration) {
        let mut current = new_tuple;

        for tuple in self.register.iter_mut() {
            tuple.dispersion += dispersion_correction;

            std::mem::swap(&mut current, tuple);
        }
    }

    fn sort_by_delay(&mut self) {
        self.register.sort_by(|t1, t2| {
            t1.delay
                .partial_cmp(&t2.delay)
                .unwrap_or_else(|| panic!("got a NaN"))
        });
    }

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
    fn dispersion(self) -> NtpDuration {
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
    fn jitter(self, s: &System) -> f64 {
        let register = self.valid_tuples();

        // for jitter, only the valid tuples are considered
        let smallest_delay = match register.get(0) {
            None => unreachable!(
                "there must be at least one valid tuple, this is guaranteed by clock_filter"
            ),
            Some(t) => t,
        };

        let root_mean_square = register
            .iter()
            .map(|t| (t.offset - smallest_delay.offset).to_seconds().powi(2))
            .sum::<f64>()
            .sqrt();

        // root mean square average (RMS average). - 1 to exclude the smallest_delay
        let jitter = root_mean_square / (register.len() - 1) as f64;

        // In order to ensure consistency and avoid divide exceptions in other
        // computations, the psi is bounded from below by the system precision
        // s.rho expressed in seconds.
        jitter.max(s.precision)
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

#[allow(dead_code)]
pub fn clock_filter(
    peer: &mut Peer,
    s: &System,
    c: &LocalClock,
    clock_offset: NtpDuration,
    roundtrip_delay: NtpDuration,
    dispersion: NtpDuration,
) {
    let new_tuple = FilterTuple {
        offset: clock_offset,
        delay: roundtrip_delay,
        dispersion,
        time: c.t,
    };

    // The clock filter contents consist of eight tuples (offset,
    // delay, dispersion, time).  Shift each tuple to the left,
    // discarding the leftmost one.  As each tuple is shifted,
    // increase the dispersion since the last filter update.  At the
    // same time, copy each tuple to a temporary list.  After this,
    // place the (offset, delay, disp, time) in the vacated
    // rightmost tuple.
    //
    // NOTE: it seems that the rightmost tuple has index 0. That is unintuitive to me,
    // may be an error in the spec? it's irrelevant because we sort
    // or use commutative/associative operations
    let dispersion_correction = (c.t - peer.t) / ONE_OVER_PHI;
    peer.clock_filter
        .shift_and_insert(new_tuple, dispersion_correction);

    let mut temporary_list = peer.clock_filter;

    temporary_list.sort_by_delay();

    let smallest_delay = temporary_list.register[0];

    let dtemp = peer.offset;
    peer.offset = smallest_delay.offset;
    peer.delay = smallest_delay.delay;

    // TODO (not in the skeleton as far as I can see)
    // If the first tuple epoch t_0 is not
    // later than the last valid sample epoch tp, the routine exits without
    // affecting the current peer variables.

    peer.dispersion = temporary_list.dispersion();
    peer.jitter = temporary_list.jitter(s);

    // Prime directive: use a sample only once and never a sample
    // older than the latest one, but anything goes before first
    // synchronized.
    if smallest_delay.time - peer.t <= NtpDuration::default() && s.leap_indicator.is_synchronized()
    {
        return;
    }

    // Popcorn spike suppressor.  Compare the difference between the
    // last and current offsets to the current jitter.  If greater
    // than SGATE (3) and if the interval since the last offset is
    // less than twice the system poll interval, dump the spike.
    // Otherwise, and if not in a burst, shake out the truechimers.
    let too_soon = (smallest_delay.time - peer.t) < (s.poll * 2i64);
    if (peer.offset - dtemp).to_seconds().abs() > SGATE * peer.jitter && too_soon {
        return;
    }

    peer.t = smallest_delay.time;
    if peer.burst_counter == 0 {
        todo!()
        // clock_select();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dispersion_of_dummys() {
        // The observer should note (a) if all stages contain the dummy tuple
        // with dispersion MAXDISP, the computed dispersion is a little less than 16 s

        let register = ClockFilterContents::new();
        let value = register.dispersion().to_seconds();

        assert!((16.0 - value) < 0.1)
    }

    #[test]
    fn dummys_are_not_valid() {
        assert!(ClockFilterContents::new().valid_tuples().is_empty())
    }

    #[test]
    #[should_panic(
        expected = "there must be at least one valid tuple, this is guaranteed by clock_filter"
    )]
    fn jitter_of_dummys() {
        // jitter only considers valid tuples, not the dummys.
        let system = System::dummy();

        let register = ClockFilterContents::new();
        let value = register.jitter(&system);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_single() {
        let mut register = ClockFilterContents::new();
        register.register[0].offset = NtpDuration::from_seconds(42.0);
        let system = System::dummy();
        let value = register.jitter(&system);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = ClockFilterContents::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(30.0);
        let system = System::dummy();
        let value = register.jitter(&system);

        // jitter is calculated relative to the first tuple
        assert!((value - 10.0).abs() < 1e-6)
    }

    #[test]
    fn jitter_of_triple() {
        let mut register = ClockFilterContents::new();
        register.register[0].offset = NtpDuration::from_seconds(20.0);
        register.register[1].offset = NtpDuration::from_seconds(20.0);
        register.register[2].offset = NtpDuration::from_seconds(30.0);
        let system = System::dummy();
        let value = register.jitter(&system);

        // jitter is calculated relative to the first tuple
        assert!((value - 5.0).abs() < 1e-6)
    }
}
