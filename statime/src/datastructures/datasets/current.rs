use crate::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CurrentDS {
    pub steps_removed: u16,
    pub offset_from_master: Duration,
    pub mean_delay: Duration,
    pub synchronization_uncertain: bool,
}
