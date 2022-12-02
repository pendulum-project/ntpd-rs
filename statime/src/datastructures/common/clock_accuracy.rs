#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockAccuracy {
    /// Reserved
    Reserved,
    /// Accurate within 1 ps
    PS1,
    /// Accurate within 2.5 ps
    PS2_5,
    /// Accurate within 10 ps
    PS10,
    /// Accurate within 25 ps
    PS25,
    /// Accurate within 100 ps
    PS100,
    /// Accurate within 250 ps
    PS250,
    /// Accurate within 1 ns
    NS1,
    /// Accurate within 2.5 ns
    NS2_5,
    /// Accurate within 10 ns
    NS10,
    /// Accurate within 25 ns
    NS25,
    /// Accurate within 100 ns
    NS100,
    /// Accurate within 250 ns
    NS250,
    /// Accurate within 1 us
    US1,
    /// Accurate within 2.5 us
    US2_5,
    /// Accurate within 10 us
    US10,
    /// Accurate within 25 us
    US25,
    /// Accurate within 100 us
    US100,
    /// Accurate within 250 us
    US250,
    /// Accurate within 1 ms
    MS1,
    /// Accurate within 2.5 ms
    MS2_5,
    /// Accurate within 10 ms
    MS10,
    /// Accurate within 25 ms
    MS25,
    /// Accurate within 100 ms
    MS100,
    /// Accurate within 250 ms
    MS250,
    /// Accurate within 1 s
    S1,
    /// Accurate within 10 s
    S10,
    /// Accurate within >10 s
    SGT10,
    /// Specific to a profile
    ProfileSpecific(u8),
    /// Accuracy is unknown
    Unknown,
}

impl ClockAccuracy {
    pub fn to_primitive(&self) -> u8 {
        match self {
            Self::Reserved => 0x00,
            Self::PS1 => 0x17,
            Self::PS2_5 => 0x18,
            Self::PS10 => 0x19,
            Self::PS25 => 0x1A,
            Self::PS100 => 0x1B,
            Self::PS250 => 0x1C,
            Self::NS1 => 0x1D,
            Self::NS2_5 => 0x1E,
            Self::NS10 => 0x1F,
            Self::NS25 => 0x20,
            Self::NS100 => 0x21,
            Self::NS250 => 0x22,
            Self::US1 => 0x23,
            Self::US2_5 => 0x24,
            Self::US10 => 0x25,
            Self::US25 => 0x26,
            Self::US100 => 0x27,
            Self::US250 => 0x28,
            Self::MS1 => 0x29,
            Self::MS2_5 => 0x2A,
            Self::MS10 => 0x2B,
            Self::MS25 => 0x2C,
            Self::MS100 => 0x2D,
            Self::MS250 => 0x2E,
            Self::S1 => 0x2F,
            Self::S10 => 0x30,
            Self::SGT10 => 0x31,
            Self::ProfileSpecific(value) => 0x80 + value,
            Self::Unknown => 0xFE,
        }
    }

    pub fn from_primitive(value: u8) -> Self {
        match value {
            0x00..=0x16 | 0x32..=0x7F | 0xFF => Self::Reserved,
            0x17 => Self::PS1,
            0x18 => Self::PS2_5,
            0x19 => Self::PS10,
            0x1A => Self::PS25,
            0x1B => Self::PS100,
            0x1C => Self::PS250,
            0x1D => Self::NS1,
            0x1E => Self::NS2_5,
            0x1F => Self::NS10,
            0x20 => Self::NS25,
            0x21 => Self::NS100,
            0x22 => Self::NS250,
            0x23 => Self::US1,
            0x24 => Self::US2_5,
            0x25 => Self::US10,
            0x26 => Self::US25,
            0x27 => Self::US100,
            0x28 => Self::US250,
            0x29 => Self::MS1,
            0x2A => Self::MS2_5,
            0x2B => Self::MS10,
            0x2C => Self::MS25,
            0x2D => Self::MS100,
            0x2E => Self::MS250,
            0x2F => Self::S1,
            0x30 => Self::S10,
            0x31 => Self::SGT10,
            0x80..=0xFD => Self::ProfileSpecific(value - 0x80),
            0xFE => ClockAccuracy::Unknown,
        }
    }
}

impl PartialOrd for ClockAccuracy {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // The clock gets more inaccurate with the higher numbers for the normal accuracy values.
        self.to_primitive()
            .partial_cmp(&other.to_primitive())
            .map(|r| r.reverse())
    }
}

impl Ord for ClockAccuracy {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Default for ClockAccuracy {
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_protocol_values() {
        for i in 0..u8::MAX {
            let protocol = ClockAccuracy::from_primitive(i);
            if !matches!(protocol, ClockAccuracy::Reserved) {
                assert_eq!(protocol.to_primitive(), i);
            }
        }

        assert_eq!(ClockAccuracy::ProfileSpecific(5).to_primitive(), 0x85);
    }
}
