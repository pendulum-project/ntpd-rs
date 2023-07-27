use crate::{
    config::InstanceConfig,
    datastructures::{
        common::{ClockIdentity, ClockQuality},
        messages::SdoId,
    },
};

/// A concrete implementation of the PTP Default dataset (IEEE1588-2019 section
/// 8.2.1)
///
/// This dataset describes the properties of the PTP instance. Most
/// instance-wide configuration options are found here, with the exception of
/// those related to timebase, which is contained in the
/// [TimePropertiesDS](crate::TimePropertiesDS) dataset.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DefaultDS {
    pub(crate) clock_identity: ClockIdentity,
    pub(crate) number_ports: u16,
    pub(crate) clock_quality: ClockQuality,
    pub(crate) priority_1: u8,
    pub(crate) priority_2: u8,
    pub(crate) domain_number: u8,
    pub(crate) slave_only: bool,
    pub(crate) sdo_id: SdoId,
}

impl DefaultDS {
    pub(crate) fn new(config: InstanceConfig) -> Self {
        Self {
            clock_identity: config.clock_identity,
            number_ports: 0,
            clock_quality: Default::default(),
            priority_1: config.priority_1,
            priority_2: config.priority_2,
            domain_number: config.domain_number,
            slave_only: config.slave_only,
            sdo_id: config.sdo_id,
        }
    }
}
