use crate::{ClockIdentity, SdoId};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct InstanceConfig {
    pub clock_identity: ClockIdentity,
    pub priority_1: u8,
    pub priority_2: u8,
    pub domain_number: u8,
    pub slave_only: bool,
    pub sdo_id: SdoId,
}
