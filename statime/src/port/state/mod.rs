use core::cell::RefCell;
use std::fmt::{Display, Formatter};

pub use master::{MasterError, MasterState};
pub use slave::{SlaveError, SlaveState};

use crate::clock::Clock;
use crate::datastructures::common::PortIdentity;
use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS};
use crate::datastructures::messages::Message;
use crate::network::NetworkPort;
use crate::port::error::Result;
use crate::time::Instant;

use super::Measurement;

mod master;
mod slave;

#[derive(Debug, Default)]
pub enum PortState {
    Disabled,
    #[default]
    Listening,
    Master(MasterState),
    Passive,
    Slave(SlaveState),
}

impl PortState {
    pub async fn send_sync<P: NetworkPort>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        network_port: &mut P,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        match self {
            PortState::Master(master) => {
                master
                    .send_sync(local_clock, network_port, port_identity, default_ds)
                    .await
            }
            PortState::Slave(_)
            | PortState::Listening
            | PortState::Disabled
            | PortState::Passive => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_announce<P: NetworkPort>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        default_ds: &DefaultDS,
        time_properties: &TimePropertiesDS,
        parent_ds: &ParentDS,
        current_ds: &CurrentDS,
        network_port: &mut P,
        port_identity: PortIdentity,
    ) -> Result<()> {
        match self {
            PortState::Master(master) => {
                master
                    .send_announce(
                        local_clock,
                        default_ds,
                        time_properties,
                        parent_ds,
                        current_ds,
                        network_port,
                        port_identity,
                    )
                    .await
            }
            PortState::Slave(_)
            | PortState::Listening
            | PortState::Disabled
            | PortState::Passive => Ok(()),
        }
    }

    pub async fn handle_message(
        &mut self,
        message: Message,
        current_time: Instant,
        network_port: &mut impl NetworkPort,
        log_message_interval: i8,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        match self {
            PortState::Master(master) => {
                master
                    .handle_message(
                        message,
                        current_time,
                        network_port,
                        log_message_interval,
                        port_identity,
                    )
                    .await?;
                Ok(())
            }
            PortState::Slave(slave) => {
                slave
                    .handle_message(
                        message,
                        current_time,
                        network_port,
                        port_identity,
                        default_ds,
                    )
                    .await?;
                Ok(())
            }
            PortState::Listening | PortState::Disabled | PortState::Passive => Ok(()),
        }
    }

    pub fn extract_measurement(&mut self) -> Option<Measurement> {
        match self {
            PortState::Slave(slave) => slave.extract_measurement(),
            PortState::Master(_)
            | PortState::Listening
            | PortState::Disabled
            | PortState::Passive => None,
        }
    }
}

impl Display for PortState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Disabled => write!(f, "Disabled"),
            PortState::Listening => write!(f, "Listening"),
            PortState::Master(_) => write!(f, "Master"),
            PortState::Passive => write!(f, "Passive"),
            PortState::Slave(_) => write!(f, "Slave"),
        }
    }
}
