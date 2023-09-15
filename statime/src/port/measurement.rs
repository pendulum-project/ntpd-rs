use crate::time::{Duration, Time};

/// A single measurement as produced by a PTP port.
/// Depending on what trigerred the measurements, not
/// all fields will be populated
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Measurement {
    /// Time this measurement was made.
    pub event_time: Time,
    /// Offset to the remote PTP node.
    pub offset: Option<Duration>,
    /// Delay to the remote PTP node.
    pub delay: Option<Duration>,
    /// Raw offset calculated from a sync message
    pub raw_sync_offset: Option<Duration>,
    /// Raw offset calculated from a delay message
    pub raw_delay_offset: Option<Duration>,
}
