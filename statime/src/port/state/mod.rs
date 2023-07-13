use core::{
    cell::RefCell,
    fmt::{Display, Formatter},
};

pub use master::MasterState;
pub use slave::SlaveState;

use super::{Measurement, PortActionIterator, TimestampContext};
use crate::{
    clock::Clock,
    datastructures::{common::PortIdentity, datasets::DefaultDS, messages::Message},
    ptp_instance::PtpInstanceState,
    time::Time,
    PortConfig,
};

mod master;
mod slave;

#[derive(Debug, Default)]
pub enum PortState {
    #[default]
    Listening,
    Master(MasterState),
    Passive,
    Slave(SlaveState),
}

impl PortState {
    pub(crate) fn handle_timestamp<'a>(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Slave(slave) => slave.handle_timestamp(context, timestamp),
            PortState::Master(master) => {
                master.handle_timestamp(context, timestamp, port_identity, default_ds, buffer)
            }
            PortState::Listening | PortState::Passive => actions![],
        }
    }

    pub(crate) fn handle_event_receive<'a>(
        &mut self,
        message: Message,
        timestamp: Time,
        min_delay_req_interval: i8,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Master(master) => master.handle_event_receive(
                message,
                timestamp,
                min_delay_req_interval,
                port_identity,
                buffer,
            ),
            PortState::Slave(slave) => {
                slave.handle_event_receive(message, timestamp, port_identity, default_ds, buffer)
            }
            PortState::Listening | PortState::Passive => actions![],
        }
    }

    pub(crate) fn handle_general_receive(&mut self, message: Message, port_identity: PortIdentity) {
        match self {
            PortState::Master(_) => {
                log::warn!("Unexpected message {:?}", message);
            }
            PortState::Slave(slave) => slave.handle_general_receive(message, port_identity),
            PortState::Listening | PortState::Passive => {}
        }
    }

    pub fn send_sync<'a>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        config: &PortConfig,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Master(master) => master.send_sync(local_clock, config, default_ds, buffer),
            PortState::Slave(_) | PortState::Listening | PortState::Passive => {
                actions![]
            }
        }
    }

    pub(crate) fn send_announce<'a, C: Clock, F>(
        &mut self,
        global: &PtpInstanceState<C, F>,
        config: &PortConfig,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Master(master) => master.send_announce(global, config, buffer),
            PortState::Slave(_) | PortState::Listening | PortState::Passive => actions![],
        }
    }

    pub fn extract_measurement(&mut self) -> Option<Measurement> {
        match self {
            PortState::Slave(slave) => slave.extract_measurement(),
            PortState::Master(_) | PortState::Listening | PortState::Passive => None,
        }
    }
}

impl Display for PortState {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PortState::Listening => write!(f, "Listening"),
            PortState::Master(_) => write!(f, "Master"),
            PortState::Passive => write!(f, "Passive"),
            PortState::Slave(_) => write!(f, "Slave"),
        }
    }
}
