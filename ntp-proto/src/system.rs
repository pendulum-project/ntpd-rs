use crate::filter::MAX_STRATUM;
use crate::{
    filter::{clock_combine, clock_select, multiply_by_phi, Peer},
    packet::NtpLeapIndicator,
    NtpDuration, NtpTimestamp,
};

// NOTE stored in exponent format in the spec
const MIN_POLL: NtpDuration = NtpDuration::from_bits_short((16u32 << 16u32).to_be_bytes()); // 16 seconds

struct System {
    time: NtpTimestamp,
    jitter: NtpDuration,
    offset: NtpDuration,

    leap: NtpLeapIndicator,
    stratum: u8,

    poll: NtpDuration,

    root_delay: NtpDuration,
    root_dispersion: NtpDuration,

    reference_id: u32,
    reference_timestamp: NtpTimestamp,
}

impl System {
    #[allow(dead_code)]
    fn clock_update(
        &mut self,
        peers: &[Peer],
        local_clock_time: NtpTimestamp,
        system_poll: NtpDuration,
    ) {
        let survivors = match clock_select(peers, local_clock_time, system_poll) {
            None => return,
            Some(v) => v,
        };

        // TODO, in the implementation (but not the spec from what I've seen)
        // the current system peer is kept if it is a survivor and it's stratum
        // is equal to the best (i.e. index 0) of the survivors
        let p = survivors[0].peer;

        if self.time >= p.time {
            return;
        }

        let combined = clock_combine(&survivors, local_clock_time);

        self.time = p.time;
        self.offset = combined.offset;
        self.jitter = combined.jitter;

        match local_clock(p, self.offset) {
            LocalClockCode::Panic => {
                // The offset is too large and probably bogus.  Complain to the
                // system log and order the operator to set the clock manually
                // within PANIC range.  The reference implementation includes a
                // command line option to disable this check and to change the
                // panic threshold from the default 1000 s as required.
                panic!("fatal error");
            }
            LocalClockCode::Step => {
                // The offset is more than the step threshold (0.125 s by
                // default).  After a step, all associations now have
                // inconsistent time values, so they are reset and started
                // fresh.  The step threshold can be changed in the reference
                // implementation in order to lessen the chance the clock might
                // be stepped backwards.  However, there may be serious
                // consequences, as noted in the white papers at the NTP project site.

                // TODO: reset all associations

                self.stratum = MAX_STRATUM;
                self.poll = MIN_POLL;
            }

            LocalClockCode::Slew => {
                // The offset was less than the step threshold, which is the
                // normal case.  Update the system variables from the peer
                // variables.  The lower clamp on the dispersion increase is to
                // avoid timing loops and clockhopping when highly precise
                // sources are in play.  The clamp can be changed from the
                // default .01 s in the reference implementation.

                self.leap = p.last_packet.leap;
                self.stratum = p.stratum;

                self.reference_id = p.last_packet.reference_id;
                self.reference_timestamp = p.last_packet.reference_timestamp;

                self.root_delay = p.last_packet.root_delay + p.statistics.delay;

                let jitter_distance = NtpDuration::from_seconds(
                    (p.statistics.jitter.powi(2) + self.jitter.to_seconds().powi(2)).sqrt(),
                );

                let lower_bound = p.statistics.dispersion
                    + multiply_by_phi(local_clock_time - p.time)
                    + p.statistics.offset.abs();

                self.root_dispersion = p.last_packet.root_dispersion
                    + NtpDuration::MIN_DISPERSION.max(lower_bound)
                    + jitter_distance;
            }
            LocalClockCode::Ignore => {
                // Some samples are discarded while, for instance, a direct
                // frequency measurement is being made.
            }
        }
    }
}

#[allow(dead_code)]
#[repr(u8)]
enum LocalClockCode {
    Ignore = 0,
    Slew = 1,
    Step = 2,
    Panic = 3,
}

fn local_clock(_peer: &Peer, _system_offset: NtpDuration) -> LocalClockCode {
    todo!()
}
