use crate::datastructures::common::{ClockIdentity, ClockQuality, PortAddress, PortIdentity};

// TODO: Discuss moving this (and TimePropertiesDS, ...) to slave?
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
