use std::time::SystemTime;

use crate::NtpTimestamp;

pub trait NtpClock {
    fn now(&self) -> NtpTimestamp;
}

pub struct SystemClock;

impl NtpClock for SystemClock {
    fn now(&self) -> NtpTimestamp {
        NtpTimestamp::from_system_time(SystemTime::now())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use crate::NtpTimestamp;

    const EPSILON: Duration = Duration::from_nanos(2);

    fn convert_duration(dur: Duration) -> NtpTimestamp {
        const EPOCH_OFFSET: u64 = (70 * 365 + 17) * 86400;

        let secs = dur.as_secs() + EPOCH_OFFSET;
        let nanos = dur.subsec_nanos();

        NtpTimestamp::from_seconds_nanos_since_ntp_epoch(secs, nanos)
    }

    #[test]
    fn conversion_unix_to_ntp() {
        // numbers based on https://gist.github.com/jmunozal/ffb4ca3d5d51bb868ee20a1427f576a9
        let s = 1649160613;
        let u = 573909;
        let actual = convert_duration(Duration::new(s, u * 1000));

        let s = 0xe5f6b025;
        let f = 0x92ebb341;
        let expected = NtpTimestamp::from_fixed_int((s << 32) | f);

        assert_eq!(actual, expected)
    }

    #[test]
    fn conversion_ntp_to_unix() {
        // numbers based on https://gist.github.com/jmunozal/ffb4ca3d5d51bb868ee20a1427f576a9
        let s = 1649160613;
        let u = 573909;
        let expected = Duration::new(s, u * 1000);

        let s = 0xe5f6b025;
        let f = 0x92ebb341;
        let actual = NtpTimestamp::from_fixed_int((s << 32) | f).duration_since_unix_epoch();

        assert!(
            expected
                .checked_sub(actual)
                .map(|a| a < EPSILON)
                .unwrap_or(true)
                && actual
                    .checked_sub(expected)
                    .map(|a| a < EPSILON)
                    .unwrap_or(true)
        );
    }

    #[test]
    fn roundtrip() {
        let timestamp = NtpTimestamp::from_fixed_int((3549086042 << 32) + 4010129364);

        let once = timestamp.duration_since_unix_epoch();
        let intermediate = convert_duration(once);

        let twice = intermediate.duration_since_unix_epoch();

        assert!(
            once.checked_sub(twice).map(|a| a < EPSILON).unwrap_or(true)
                && twice.checked_sub(once).map(|a| a < EPSILON).unwrap_or(true)
        );
    }
}
