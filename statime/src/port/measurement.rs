use crate::time::{Duration, Instant};

#[derive(Debug, Eq, PartialEq)]
pub struct Measurement {
    pub event_time: Instant,
    pub master_offset: Duration,
}
