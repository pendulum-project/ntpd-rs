// An implementation of the NTP clock filter algorithm, as described by
//
//      https://datatracker.ietf.org/doc/html/rfc5905#page-37
//
// Specifically this is a rust implementation of the `clock_filter()` routine,
// described in the appendix
//
//      https://datatracker.ietf.org/doc/html/rfc5905#appendix-A.5.2

use crate::{NtpDuration, NtpTimestamp};

/// clock register stages
const NSTAGE: usize = 8;

/// leap unsync
const NOSYNC: i8 = 0x3;

/// frequency tolerance (15 ppm)
const PHI: f64 = 15e-6;
const ONE_OVER_PHI: i64 = 15_000_000;

/// spike gate (clock filter)
const SGATE: f64 = 3.0;

struct Peer {
    offset: f64,
    delay: f64,
    dispersion: NtpDuration,
    jitter: f64,
    t: NtpTimestamp,
    clock_filter: [FilterTuple; 8],
    /// burst counter
    burst: u32, // i32 in the source
}

struct System {
    precision: i8,
    leap: i8,
    poll: ExponentFormat,
}

struct LocalClock {
    t: NtpTimestamp, /* update time */
    state: i32,      /* current state */
    offset: f64,     /* current offset */
    last: f64,       /* previous offset */
    count: i32,      /* jiggle counter */
    freq: f64,       /* frequency */
    jitter: f64,     /* RMS jitter */
    wander: f64,     /* RMS wander */
}

#[derive(Debug, Clone, Copy)]
struct FilterTuple {
    offset: f64,
    delay: f64,
    dispersion: NtpDuration,
    time: NtpTimestamp,
}

struct ExponentFormat(i8);

impl ExponentFormat {
    fn exponent(&self) -> i8 {
        self.0
    }

    // taken from `double UTI_Log2ToDouble(int l)`
    fn as_f64(&self) -> f64 {
        let l = self.0 as i32;

        // fun fact: shifting by 32 or more bits is UB
        if l >= 0 {
            let amount = 31.min(l);
            (1u32 << amount) as f64
        } else {
            let amount = (-31).max(l);
            1.0f64 / (1u32 << -amount) as f64
        }
    }

    fn as_timestamp(&self) -> NtpTimestamp {
        NtpTimestamp::from_bits((self.as_f64() as u64).to_be_bytes())
    }

    fn as_duration(&self) -> NtpDuration {
        self.as_timestamp() - NtpTimestamp::default()
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

fn clock_filter(
    peer: &mut Peer,
    s: &System,
    c: &LocalClock,
    clock_offset: f64,
    roundtrip_delay: f64,
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
    let mut temporary_list = shift_filter(&mut peer.clock_filter, new_tuple, dispersion_correction);

    // Sort the temporary list of tuples by increasing f[].delay.
    // The first entry on the sorted list represents the best
    // sample, but it might be old.
    temporary_list.sort_by(|t1, t2| {
        t1.delay
            .partial_cmp(&t2.delay)
            .unwrap_or_else(|| panic!("got a NaN"))
    });

    let smallest_delay = temporary_list[0];

    let dtemp = peer.offset;
    peer.offset = smallest_delay.offset;
    peer.delay = smallest_delay.delay;

    for (i, tuple) in temporary_list.iter().enumerate() {
        peer.dispersion += tuple.dispersion / (2i64.pow(i as u32 + 1));
        peer.jitter += (tuple.offset - smallest_delay.offset).powf(2.0);
    }

    peer.jitter = (peer.jitter.sqrt()).max(log2d(s.precision));

    // Prime directive: use a sample only once and never a sample
    // older than the latest one, but anything goes before first
    // synchronized.
    if smallest_delay.time - peer.t <= NtpDuration::default() && s.leap != NOSYNC {
        return;
    }

    // Popcorn spike suppressor.  Compare the difference between the
    // last and current offsets to the current jitter.  If greater
    // than SGATE (3) and if the interval since the last offset is
    // less than twice the system poll interval, dump the spike.
    // Otherwise, and if not in a burst, shake out the truechimers.
    let too_soon = (smallest_delay.time - peer.t) < (s.poll.as_duration() + s.poll.as_duration());
    if (peer.offset - dtemp).abs() > SGATE * peer.jitter && too_soon {
        return;
    }

    peer.t = smallest_delay.time;
    if peer.burst == 0 {
        todo!()
        // clock_select();
    }
}

/// so actually this looks more like the inverse of a logarithm. The
/// `input` is a value stored in `log2` format. So `input = log2(output)`, we get x
/// and output y
fn log2d(input: i8) -> f64 {
    if input < 0 {
        // 1. / (1L << -(a))
        1.0 / (1i64 << -input) as f64
    } else {
        // 1L << (a)
        (1i64 << input) as f64
    }
}

fn main() {
    let _ = clock_filter;
    println!("Hello, world!");
}
