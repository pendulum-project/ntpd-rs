use core::fmt::{Display, Formatter};

use rand::Rng;

use super::{PortActionIterator, TimestampContext};
use crate::{
    datastructures::{common::PortIdentity, datasets::DefaultDS, messages::Message},
    ptp_instance::PtpInstanceState,
    time::{Interval, Time},
    Clock, Filter, PortConfig,
};

mod master;
mod slave;

pub(crate) use master::MasterState;
pub(crate) use slave::SlaveState;

#[derive(Debug, Default)]
pub(crate) enum PortState<F> {
    #[default]
    Listening,
    Master(MasterState),
    Passive,
    Slave(SlaveState<F>),
}

impl<F: Filter> PortState<F> {
    pub(crate) fn handle_timestamp<'a, C: Clock>(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        clock: &mut C,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Slave(slave) => slave.handle_timestamp(context, timestamp, clock),
            PortState::Master(master) => {
                master.handle_timestamp(context, timestamp, port_identity, default_ds, buffer)
            }
            PortState::Listening | PortState::Passive => actions![],
        }
    }

    pub(crate) fn handle_event_receive<'a, C: Clock>(
        &mut self,
        message: Message,
        timestamp: Time,
        min_delay_req_interval: Interval,
        port_identity: PortIdentity,
        clock: &mut C,
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
            PortState::Slave(slave) => slave.handle_event_receive(message, timestamp, clock),
            PortState::Listening | PortState::Passive => actions![],
        }
    }

    pub(crate) fn handle_general_receive<C: Clock>(
        &mut self,
        message: Message,
        port_identity: PortIdentity,
        clock: &mut C,
    ) -> PortActionIterator {
        match self {
            PortState::Master(_) => {
                if message.header().source_port_identity != port_identity {
                    log::warn!("Unexpected message {:?}", message);
                }
                actions![]
            }
            PortState::Slave(slave) => slave.handle_general_receive(message, port_identity, clock),
            PortState::Listening | PortState::Passive => {
                actions![]
            }
        }
    }

    pub(crate) fn handle_filter_update<C: Clock>(&mut self, clock: &mut C) -> PortActionIterator {
        match self {
            PortState::Slave(slave) => slave.handle_filter_update(clock),
            PortState::Master(_) | PortState::Listening | PortState::Passive => {
                actions![]
            }
        }
    }

    pub(crate) fn demobilize_filter<C: Clock>(&mut self, clock: &mut C) {
        match self {
            PortState::Slave(slave) => slave.demobilize_filter(clock),
            PortState::Master(_) | PortState::Listening | PortState::Passive => {}
        }
    }
}

impl<F> PortState<F> {
    pub(crate) fn send_sync<'a>(
        &mut self,
        config: &PortConfig,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Master(master) => {
                master.send_sync(config, port_identity, default_ds, buffer)
            }
            PortState::Slave(_) | PortState::Listening | PortState::Passive => {
                actions![]
            }
        }
    }

    pub(crate) fn send_delay_request<'a>(
        &mut self,
        rng: &mut impl Rng,
        port_config: &PortConfig,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Slave(slave) => {
                slave.send_delay_request(rng, port_config, port_identity, default_ds, buffer)
            }
            PortState::Master(_) | PortState::Listening | PortState::Passive => {
                actions![]
            }
        }
    }

    pub(crate) fn send_announce<'a>(
        &mut self,
        global: &PtpInstanceState,
        config: &PortConfig,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match self {
            PortState::Master(master) => {
                master.send_announce(global, config, port_identity, buffer)
            }
            PortState::Slave(_) | PortState::Listening | PortState::Passive => actions![],
        }
    }
}

impl<F> Display for PortState<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PortState::Listening => write!(f, "Listening"),
            PortState::Master(_) => write!(f, "Master"),
            PortState::Passive => write!(f, "Passive"),
            PortState::Slave(_) => write!(f, "Slave"),
        }
    }
}
