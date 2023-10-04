#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Interval(i8);

impl core::fmt::Debug for Interval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Interval")
            .field("seconds", &self.as_f64())
            .field("log_base_2", &self.0)
            .finish()
    }
}

impl Interval {
    pub const ONE_SECOND: Self = Self(0);
    pub const TWO_SECONDS: Self = Self(1);

    pub const fn from_log_2(log_2: i8) -> Self {
        Self(log_2)
    }

    pub fn seconds(self) -> f64 {
        self.as_f64()
    }

    pub fn as_duration(self) -> super::Duration {
        super::Duration::from_interval(self)
    }

    pub fn as_core_duration(self) -> core::time::Duration {
        core::time::Duration::from_secs_f64(self.seconds())
    }

    #[cfg(not(feature = "std"))]
    pub fn as_f64(self) -> f64 {
        libm::pow(2.0f64, self.0 as f64)
    }

    #[cfg(feature = "std")]
    pub fn as_f64(self) -> f64 {
        2.0f64.powi(self.0 as i32)
    }

    pub fn as_log_2(self) -> i8 {
        self.0
    }
}

impl From<i8> for Interval {
    fn from(value: i8) -> Self {
        Self::from_log_2(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two() {
        assert_eq!(Interval::TWO_SECONDS.as_f64(), 2.0f64)
    }
}
