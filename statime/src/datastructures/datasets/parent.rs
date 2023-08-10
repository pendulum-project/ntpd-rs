use super::DefaultDS;
use crate::datastructures::common::{ClockIdentity, ClockQuality, PortIdentity};

// TODO: Discuss moving this (and TimePropertiesDS, ...) to slave?
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParentDS {
    pub(crate) parent_port_identity: PortIdentity,
    pub(crate) parent_stats: bool,
    pub(crate) observed_parent_offset_scaled_log_variance: u16,
    pub(crate) observed_parent_clock_phase_change_rate: u32,
    pub(crate) grandmaster_identity: ClockIdentity,
    pub(crate) grandmaster_clock_quality: ClockQuality,
    pub(crate) grandmaster_priority_1: u8,
    pub(crate) grandmaster_priority_2: u8,
}

impl ParentDS {
    pub(crate) fn new(default_ds: DefaultDS) -> Self {
        ParentDS {
            parent_port_identity: PortIdentity {
                clock_identity: default_ds.clock_identity,
                port_number: 0,
            },
            parent_stats: false,
            observed_parent_offset_scaled_log_variance: 0xffff,
            observed_parent_clock_phase_change_rate: 0x7fffffff,
            grandmaster_identity: default_ds.clock_identity,
            grandmaster_clock_quality: default_ds.clock_quality,
            grandmaster_priority_1: default_ds.priority_1,
            grandmaster_priority_2: default_ds.priority_2,
        }
    }
}
