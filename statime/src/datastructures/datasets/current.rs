use crate::time::Duration;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CurrentDS {
    steps_removed: u16,
    offset_from_master: Duration,
    mean_delay: Duration,
    synchronization_uncertain: bool,
}
