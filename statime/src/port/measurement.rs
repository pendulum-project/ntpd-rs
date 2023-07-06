use crate::time::{Duration, Time};

/// A single measurement as produced by a PTP port.
#[derive(Debug, Eq, PartialEq)]
pub struct Measurement {
    /// Time this measurement was made.
    pub event_time: Time,
    /// Offset to the remote PTP node.
    pub master_offset: Duration,
}
