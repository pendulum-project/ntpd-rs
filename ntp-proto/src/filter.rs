// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::{NtpDuration, NtpTimestamp};

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

    fn new_register() -> [Self; 8] {
        [Self::dummy(); 8]
    }
}

fn shift_filter(
    clock_filter: &mut [FilterTuple; 8],
    new_tuple: FilterTuple,
    dispersion_correction: NtpDuration,
) -> [FilterTuple; 8] {
    let mut current = new_tuple;

    for tuple in clock_filter.iter_mut() {
        tuple.dispersion += dispersion_correction;

        std::mem::swap(&mut current, tuple);
    }

    *clock_filter
}

/// #[no_run]
///                     i=n-1
///                     ---     epsilon_i
///      epsilon =       \     ----------
///                      /        (i+1)
///                     ---     2
///                     i=0
fn calculate_peer_dispersion(sorted_tuples: &[FilterTuple; 8]) -> NtpDuration {
    sorted_tuples
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
fn calculate_peer_jitter(s: &System, sorted_tuples: &[FilterTuple]) -> f64 {
    let smallest_delay = sorted_tuples[0];

    let root_mean_square = sorted_tuples
        .iter()
        .map(|t| (t.offset - smallest_delay.offset).to_seconds().powi(2))
        .sum::<f64>()
        .sqrt();

    // root mean square average (RMS average). - 1 to exclude the smallest_delay
    let jitter = root_mean_square / (sorted_tuples.len() - 1) as f64;

    // In order to ensure consistency and avoid divide exceptions in other
    // computations, the psi is bounded from below by the system precision
    // s.rho expressed in seconds.
    jitter.max(s.precision)
}

struct System {
    precision: f64,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dispersion_of_dummys() {
        // The observer should note (a) if all stages contain the dummy tuple
        // with dispersion MAXDISP, the computed dispersion is a little less than 16 s

        let register = FilterTuple::new_register();
        let value = calculate_peer_dispersion(&register).to_seconds();

        assert!((16.0 - value) < 0.1)
    }

    #[test]
    fn jitter_of_dummys() {
        // jitter only considers valid tuples, not the dummys.
        // So this should just do nothing and return 0

        let system = System { precision: 0.0 };
        let value = calculate_peer_jitter(&system, &[]);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_single() {
        let mut register = FilterTuple::new_register();
        register[0].offset = NtpDuration::from_seconds(42.0);
        let system = System { precision: 0.0 };
        let value = calculate_peer_jitter(&system, &register[..1]);

        assert_eq!(value, 0.0)
    }

    #[test]
    fn jitter_of_pair() {
        let mut register = FilterTuple::new_register();
        register[0].offset = NtpDuration::from_seconds(20.0);
        register[1].offset = NtpDuration::from_seconds(30.0);
        let system = System { precision: 0.0 };
        let value = calculate_peer_jitter(&system, &register[..2]);

        // jitter is calculated relative to the first tuple
        assert!((value - 10.0).abs() < 1e-6)
    }

    #[test]
    fn jitter_of_triple() {
        let mut register = FilterTuple::new_register();
        register[0].offset = NtpDuration::from_seconds(20.0);
        register[1].offset = NtpDuration::from_seconds(20.0);
        register[2].offset = NtpDuration::from_seconds(30.0);
        let system = System { precision: 0.0 };
        let value = calculate_peer_jitter(&system, &register[..3]);

        // jitter is calculated relative to the first tuple
        assert!((value - 5.0).abs() < 1e-6)
    }
}
