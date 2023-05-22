use crate::{
    datastructures::{
        common::{ClockIdentity, ClockQuality, InstanceType},
        messages::SdoId,
    },
    time::Instant,
};

/// A concrete implementation of the PTP Default dataset (IEEE1588-2019 section
/// 8.2.1)
///
/// This dataset describes the properties of the PTP instance. Most
/// instance-wide configuration options are found here, with the exception of
/// those related to timebase, which is contained in the
/// [TimePropertiesDS](crate::TimePropertiesDS) dataset.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DefaultDS {
    pub(crate) clock_identity: ClockIdentity,
    number_ports: u16,
    pub(crate) clock_quality: ClockQuality,
    pub(crate) priority_1: u8,
    pub(crate) priority_2: u8,
    pub(crate) domain_number: u8,
    slave_only: bool,
    pub(crate) sdo_id: SdoId,
    current_time: Instant,
    pub(crate) instance_enable: bool,
    external_port_configuration_enabled: bool,
    max_steps_removed: u8,
    pub(crate) instance_type: InstanceType,
}

impl DefaultDS {
    /// Create a Default dataset for an ordinary clock
    ///
    /// The `domain_number` and `sdo_id` together control which time network the
    /// clock connects to. SDO id's are assigned through the PTP standard, and
    /// allowed values for domain numbers are specified in the assignment. A PTP
    /// instance will only communicate with instances with matching domain and
    /// sdo id.
    ///
    /// The priority values are used in selecting the primary time source within
    /// a ptp network. A clock with a higher `priority_1` is always preferred.
    /// The `priority_2` field is only used as a tiebreaker among nodes in the
    /// PTP network that have both identical `priority_1` values and advertise
    /// clock/time precision that are identical.
    ///
    /// `clock_identity` should be the identifier for this clock. It should
    /// typically be derived from the mac address of one of the interfaces of
    /// the device running the PTP instance, as described in IEEE1588-2019
    /// section 7.5.2.2.
    pub fn new_ordinary_clock(
        clock_identity: ClockIdentity,
        priority_1: u8,
        priority_2: u8,
        domain_number: u8,
        slave_only: bool,
        sdo_id: SdoId,
    ) -> Self {
        DefaultDS {
            clock_identity,
            number_ports: 1,
            clock_quality: Default::default(),
            priority_1,
            priority_2,
            domain_number,
            slave_only,
            sdo_id,
            current_time: Default::default(),
            instance_enable: true,
            external_port_configuration_enabled: false,
            max_steps_removed: 255,
            instance_type: InstanceType::OrdinaryClock,
        }
    }

    /// Create a Default dataset for an boundary clock
    ///
    /// The `domain_number` and `sdo_id` together control which time network the
    /// clock connects to. SDO id's are assigned through the PTP standard, and
    /// allowed values for domain numbers are specified in the assignment. A PTP
    /// instance will only communicate with instances with matching domain and
    /// sdo id.
    ///
    /// The priority values are used in selecting the primary time source within
    /// a ptp network. A clock with a higher `priority_1` is always preferred.
    /// The `priority_2` field is only used as a tiebreaker among nodes in the
    /// PTP network that have both identical `priority_1` values and advertise
    /// clock/time precision that are identical.
    ///
    /// `clock_identity` should be the identifier for this clock. It should
    /// typically be derived from the mac address of one of the interfaces of
    /// the device running the PTP instance, as described in IEEE1588-2019
    /// section 7.5.2.2.
    pub fn new_boundary_clock(
        clock_identity: ClockIdentity,
        number_ports: u16,
        priority_1: u8,
        priority_2: u8,
        domain_number: u8,
        sdo_id: SdoId,
    ) -> Self {
        DefaultDS {
            clock_identity,
            number_ports,
            clock_quality: Default::default(),
            priority_1,
            priority_2,
            domain_number,
            // Not applicable
            slave_only: false,
            sdo_id,
            current_time: Default::default(),
            instance_enable: true,
            external_port_configuration_enabled: false,
            max_steps_removed: 255,
            instance_type: InstanceType::BoundaryClock,
        }
    }
}
