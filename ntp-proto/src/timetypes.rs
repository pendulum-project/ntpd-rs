use std::{ops::Sub, time::Duration};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct NtpTimestamp {
    timestamp: u64,
}

/// Unix uses an epoch located at 1/1/1970-00:00h (UTC) and NTP uses 1/1/1900-00:00h.
/// This leads to an offset equivalent to 70 years in seconds
/// (there are 17 leap years between the two dates so the offset is
const EPOCH_OFFSET: u64 = (70 * 365 + 17) * 86400;

impl NtpTimestamp {
    pub(crate) const fn from_bits(bits: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp {
            timestamp: u64::from_be_bytes(bits),
        }
    }

    pub(crate) const fn to_bits(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }

    pub(crate) fn from_system_time(time: std::time::SystemTime) -> Self {
        let dur = time.duration_since(std::time::UNIX_EPOCH).unwrap();
        let secs = dur.as_secs() + EPOCH_OFFSET;
        let nanos = dur.subsec_nanos();

        Self::from_seconds_nanos_since_ntp_epoch(secs, nanos)
    }

    pub(crate) fn from_seconds_nanos_since_ntp_epoch(seconds: u64, nanos: u32) -> Self {
        // NTP uses 1/2^32 sec as its unit of fractional time.
        // our time is in nanoseconds, so 1/1e9 seconds
        let fraction = ((nanos as u64) << 32) / 1_000_000_000;

        // alternatively, abuse FP arithmetic to save an instruction
        // let fraction = (nanos as f64 * 4.294967296) as u64;

        let timestamp = (seconds << 32) + fraction;
        NtpTimestamp::from_bits(timestamp.to_be_bytes())
    }

    #[cfg(test)]
    pub(crate) fn duration_since_unix_epoch(self) -> Duration {
        let seconds = (self.seconds() as u64) - EPOCH_OFFSET;
        let nanos = ((self.fraction() as u64) * 1_000_000_000 / (1u64 << 32)) as u32;

        Duration::new(seconds, nanos)
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(timestamp: u64) -> NtpTimestamp {
        NtpTimestamp { timestamp }
    }

    #[cfg(test)]
    pub(crate) const fn seconds(self) -> u32 {
        (self.timestamp >> 32) as u32
    }

    #[cfg(test)]
    pub(crate) const fn fraction(self) -> u32 {
        self.timestamp as u32
    }
}

impl Sub for NtpTimestamp {
    type Output = NtpDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        NtpDuration {
            duration: self.timestamp as i64 - rhs.timestamp as i64,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct NtpDuration {
    duration: i64,
}

impl NtpDuration {
    pub(crate) const fn from_bits_short(bits: [u8; 4]) -> NtpDuration {
        NtpDuration {
            duration: (u32::from_be_bytes(bits) as i64) << 16,
        }
    }

    pub(crate) const fn to_bits_short(self) -> [u8; 4] {
        assert!(self.duration >= 0);
        assert!(self.duration <= 0x0000FFFFFFFFFFFF);
        (((self.duration & 0x0000FFFFFFFF0000) >> 16) as u32).to_be_bytes()
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(duration: i64) -> NtpDuration {
        NtpDuration { duration }
    }
}
