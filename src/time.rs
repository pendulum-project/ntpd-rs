use crate::datastructures::common::{TimeInterval, Timestamp};
use fixed::{
    traits::{LosslessTryInto, ToFixed},
    types::I112F16,
};
use nix::sys::time::TimeSpec;

/// Time in nanoseconds
pub type OffsetTime = I112F16;

#[derive(Clone, Debug)]
pub struct RangeError {}

pub trait TimeType {
    fn from_timespec(spec: &TimeSpec) -> Self;
    fn from_timestamp(ts: &Timestamp) -> Self;
    fn from_interval(interval: &TimeInterval) -> Self;
    fn from_log_interval(log_interval: i8) -> Self;
    fn to_timestamp(&self) -> Result<Timestamp, RangeError>;
    fn to_interval(&self) -> Result<TimeInterval, RangeError>;
    fn secs(&self) -> i128;
    fn sub_nanos(&self) -> u32;
}

impl TimeType for OffsetTime {
    fn from_timespec(spec: &TimeSpec) -> Self {
        (spec.tv_sec() as i128 * 1_000_000_000i128 + spec.tv_nsec() as i128).to_fixed()
    }

    fn from_timestamp(ts: &Timestamp) -> Self {
        (ts.seconds as i128 * 1_000_000_000i128 + ts.nanos as i128).to_fixed()
    }

    fn from_interval(interval: &TimeInterval) -> Self {
        interval.0.into()
    }

    fn to_timestamp(&self) -> Result<Timestamp, RangeError> {
        Ok(Timestamp {
            seconds: self.secs().checked_abs().unwrap() as u64,
            nanos: self.sub_nanos(),
        })
    }

    fn to_interval(&self) -> Result<TimeInterval, RangeError> {
        let val = (*self).lossless_try_into().ok_or(RangeError {})?;
        Ok(TimeInterval(val))
    }

    fn secs(&self) -> i128 {
        self.to_num::<i128>() / 1000000000i128
    }

    fn sub_nanos(&self) -> u32 {
        (self.to_num::<i128>() % 1000000000i128) as u32
    }

    fn from_log_interval(log_interval: i8) -> Self {
        let seconds = 2.0f64.powi(log_interval as i32);
        let nanos = seconds * 1_000_000_000.0;
        nanos.to_fixed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_interval() {
        assert_eq!(OffsetTime::from_log_interval(0), 1000000000u64.to_fixed::<OffsetTime>());
        assert_eq!(OffsetTime::from_log_interval(-1), 500000000u64.to_fixed::<OffsetTime>());
        assert_eq!(OffsetTime::from_log_interval(1), 2000000000u64.to_fixed::<OffsetTime>());
    }
}
