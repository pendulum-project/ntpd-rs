use crate::datastructures::common::ClockIdentity;
use crate::datastructures::common::ClockQuality;
use crate::datastructures::common::InstanceType;
use crate::time::Instant;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DefaultDS {
    pub clock_identity: ClockIdentity,
    pub number_ports: u16,
    pub clock_quality: ClockQuality,
    pub priority1: u8,
    pub priority2: u8,
    pub domain_number: u8,
    pub slave_only: bool,
    // TODO: 12 bit number -_-
    pub sdo_id: (),
    pub current_time: Instant,
    pub instance_enable: bool,
    pub external_port_configuration_enabled: bool,
    pub max_steps_removed: u8,
    pub instance_type: InstanceType,
}

impl DefaultDS {
    pub fn new_oc(
        clock_identity: ClockIdentity,
        priority1: u8,
        priority2: u8,
        domain_number: u8,
        slave_only: bool,
    ) -> Self {
        DefaultDS {
            clock_identity,
            number_ports: 1,
            clock_quality: Default::default(),
            priority1,
            priority2,
            domain_number,
            slave_only,
            sdo_id: (),
            current_time: Default::default(),
            instance_enable: true,
            external_port_configuration_enabled: false,
            max_steps_removed: 255,
            instance_type: InstanceType::OrdinaryClock,
        }
    }

    pub fn new_bc(
        clock_identity: ClockIdentity,
        number_ports: u16,
        priority1: u8,
        priority2: u8,
        domain_number: u8,
    ) -> Self {
        DefaultDS {
            clock_identity,
            number_ports,
            clock_quality: Default::default(),
            priority1,
            priority2,
            domain_number,
            // Not applicable
            slave_only: false,
            sdo_id: (),
            current_time: Default::default(),
            instance_enable: true,
            external_port_configuration_enabled: false,
            max_steps_removed: 255,
            instance_type: InstanceType::BoundaryClock,
        }
    }
}
