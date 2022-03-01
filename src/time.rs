use std::time::SystemTime;

use fixed::{
    traits::{LosslessTryInto, ToFixed},
    types::I112F16,
};
use nix::sys::time::TimeSpec;

use crate::datastructures::common::{TimeInterval, Timestamp};

/// Time in nanoseconds
pub type OffsetTime = I112F16;

#[derive(Clone, Debug)]
pub struct RangeError {}

pub trait TimeType {
    fn now() -> Self;
    fn from_timespec(spec: &TimeSpec) -> Self;
    fn from_timestamp(ts: &Timestamp) -> Self;
    fn from_interval(interval: &TimeInterval) -> Self;
    fn to_timestamp(&self) -> Result<Timestamp, RangeError>;
    fn to_interval(&self) -> Result<TimeInterval, RangeError>;
    fn secs(&self) -> i128;
    fn sub_nanos(&self) -> u32;
}

impl TimeType for OffsetTime {
    fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        now.as_nanos().to_fixed()
    }

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
        let seconds: u64 = self.checked_to_num().ok_or(RangeError {})?;
        Ok(Timestamp {
            seconds,
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
}
