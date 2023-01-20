use crate::datastructures::common::{ClockIdentity, ClockQuality, PortAddress, PortIdentity};
use crate::datastructures::datasets::default::DefaultDS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentDS {
    pub parent_port_identity: PortIdentity,
    pub parent_stats: bool,
    pub observed_parent_offset_scaled_log_variance: u16,
    pub observed_parent_clock_phase_change_rate: u32,
    pub grandmaster_identity: ClockIdentity,
    pub grandmaster_clock_quality: ClockQuality,
    pub grandmaster_priority_1: u8,
    pub grandmaster_priority_2: u8,
    pub protocol_address: PortAddress,
    pub synchronization_uncertain: bool,
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
