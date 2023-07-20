use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// How accurate the underlying clock device is expected to be when not
/// synchronized.
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
            Self::PS25 => 0x1a,
            Self::PS100 => 0x1b,
            Self::PS250 => 0x1c,
            Self::NS1 => 0x1d,
            Self::NS2_5 => 0x1e,
            Self::NS10 => 0x1f,
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
            Self::MS2_5 => 0x2a,
            Self::MS10 => 0x2b,
            Self::MS25 => 0x2c,
            Self::MS100 => 0x2d,
            Self::MS250 => 0x2e,
            Self::S1 => 0x2f,
            Self::S10 => 0x30,
            Self::SGT10 => 0x31,
            Self::ProfileSpecific(value) => 0x80 + value,
            Self::Unknown => 0xfe,
        }
    }

    pub fn from_primitive(value: u8) -> Self {
        match value {
            0x00..=0x16 | 0x32..=0x7f | 0xff => Self::Reserved,
            0x17 => Self::PS1,
            0x18 => Self::PS2_5,
            0x19 => Self::PS10,
            0x1a => Self::PS25,
            0x1b => Self::PS100,
            0x1c => Self::PS250,
            0x1d => Self::NS1,
            0x1e => Self::NS2_5,
            0x1f => Self::NS10,
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
            0x2a => Self::MS2_5,
            0x2b => Self::MS10,
            0x2c => Self::MS25,
            0x2d => Self::MS100,
            0x2e => Self::MS250,
            0x2f => Self::S1,
            0x30 => Self::S10,
            0x31 => Self::SGT10,
            0x80..=0xfd => Self::ProfileSpecific(value - 0x80),
            0xfe => ClockAccuracy::Unknown,
        }
    }

    /// low accuracy to high accuracy
    ///
    /// ```
    /// use core::cmp::Ordering;
    /// use statime::ClockAccuracy;
    /// // PS1 has a higher accuracy than PS10
    /// assert_eq!(ClockAccuracy::PS1.cmp_semantic(&ClockAccuracy::PS10), Ordering::Greater);
    /// ```
    pub fn cmp_semantic(&self, other: &Self) -> Ordering {
        // this comparison is flipped by design: The clock gets more inaccurate with the
        // higher numbers for the normal accuracy values. so a clock with a
        // lower inaccuracy is better in the ordering of clocks
        self.cmp_numeric(other).reverse()
    }

    /// high accuracy to low accuracy
    ///
    /// ```
    /// use core::cmp::Ordering;
    /// use statime::ClockAccuracy;
    /// // the inaccuracy of PS1 is less than of PS10
    /// assert_eq!(ClockAccuracy::PS1.cmp_numeric(&ClockAccuracy::PS10), Ordering::Less);
    /// ```
    pub fn cmp_numeric(&self, other: &Self) -> Ordering {
        self.to_primitive().cmp(&other.to_primitive())
    }
}

impl Default for ClockAccuracy {
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

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

    #[test]
    fn ordering() {
        let a = ClockAccuracy::PS1;
        let b = ClockAccuracy::PS10;

        assert_eq!(a.cmp_semantic(&b), Ordering::Greater);
    }
}
