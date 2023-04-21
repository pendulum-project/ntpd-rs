use crate::datastructures::common::{ClockIdentity, ClockQuality, PortAddress, PortIdentity};

// TODO: Discuss moving this (and TimePropertiesDS, ...) to slave?
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct ParentDS {
    pub(crate) parent_port_identity: PortIdentity,
    pub(crate) parent_stats: bool,
    pub(crate) observed_parent_offset_scaled_log_variance: u16,
    pub(crate) observed_parent_clock_phase_change_rate: u32,
    pub(crate) grandmaster_identity: ClockIdentity,
    pub(crate) grandmaster_clock_quality: ClockQuality,
    pub(crate) grandmaster_priority_1: u8,
    pub(crate) grandmaster_priority_2: u8,
    pub(crate) protocol_address: PortAddress,
}
