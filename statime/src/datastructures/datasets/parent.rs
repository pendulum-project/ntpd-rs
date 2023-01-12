use crate::datastructures::common::{ClockIdentity, ClockQuality, PortAddress, PortIdentity};
use crate::datastructures::datasets::default::DefaultDS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentDS {
    parent_port_identity: PortIdentity,
    parent_stats: bool,
    observed_parent_offset_scaled_log_variance: u16,
    observed_parent_clock_phase_change_rate: u32,
    grandmaster_identity: ClockIdentity,
    grandmaster_clock_quality: ClockQuality,
    grandmaster_priority_1: u8,
    grandmaster_priority_2: u8,
    protocol_address: PortAddress,
    synchronization_uncertain: bool,
}

impl ParentDS {
    pub fn new(default_ds: &DefaultDS) -> Self {
        let parent_port_identity = PortIdentity {
            clock_identity: default_ds.clock_identity,
            port_number: 0,
        };
        let protocol_address = todo!();

        ParentDS {
            parent_port_identity,
            parent_stats: false,
            observed_parent_offset_scaled_log_variance: 0xFFFF,
            observed_parent_clock_phase_change_rate: 0x7FFF_FFFF,
            grandmaster_identity: default_ds.clock_identity,
            grandmaster_clock_quality: default_ds.clock_quality,
            grandmaster_priority_1: default_ds.priority_1,
            grandmaster_priority_2: default_ds.priority_2,
            protocol_address,
            synchronization_uncertain: false,
        }
    }
}
