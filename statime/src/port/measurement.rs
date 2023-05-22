use crate::time::{Duration, Instant};

/// A single measurement as produced by a PTP port.
#[derive(Debug, Eq, PartialEq)]
pub struct Measurement {
    /// Time this measurement was made.
    pub event_time: Instant,
    /// Offset to the remote PTP node.
    pub master_offset: Duration,
}
