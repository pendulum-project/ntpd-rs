use std::ops::Sub;

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct NtpTimestamp {
    timestamp: u64,
}

impl Default for NtpTimestamp {
    fn default() -> Self {
        Self::from_bits([0u8; 8])
    }
}

impl NtpTimestamp {
    pub(crate) const fn from_bits(bits: [u8; 8]) -> NtpTimestamp {
        NtpTimestamp {
            timestamp: u64::from_be_bytes(bits),
        }
    }

    pub(crate) const fn to_bits(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(timestamp: u64) -> NtpTimestamp {
        NtpTimestamp { timestamp }
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct NtpDuration {
    duration: i64,
}

impl Default for NtpDuration {
    fn default() -> Self {
        Self::from_bits_short([0u8; 4])
    }
}

impl NtpDuration {
    pub(crate) const fn from_bits_short(bits: [u8; 4]) -> NtpDuration {
        NtpDuration {
            duration: (u32::from_be_bytes(bits) as i64) << 16,
        }
    }

    pub(crate) const fn to_bits_short(&self) -> [u8; 4] {
        assert!(self.duration >= 0);
        assert!(self.duration <= 0x0000FFFFFFFFFFFF);
        (((self.duration & 0x0000FFFFFFFF0000) >> 16) as u32).to_be_bytes()
    }

    #[cfg(test)]
    pub(crate) const fn from_fixed_int(duration: i64) -> NtpDuration {
        NtpDuration { duration }
    }
}
