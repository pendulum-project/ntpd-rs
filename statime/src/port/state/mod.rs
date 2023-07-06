use core::{
    cell::RefCell,
    fmt::{Display, Formatter},
};

pub use master::{MasterError, MasterState};
pub use slave::{SlaveError, SlaveState};

use super::Measurement;
use crate::{
    clock::Clock,
    datastructures::{
        common::PortIdentity,
        datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
        messages::Message,
    },
    network::NetworkPort,
    port::error::Result,
    time::Time,
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
            PortState::Slave(_) | PortState::Listening | PortState::Passive => Ok(()),
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
            PortState::Slave(_) | PortState::Listening | PortState::Passive => Ok(()),
        }
    }

    pub async fn handle_message(
        &mut self,
        message: Message,
        current_time: Time,
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
            PortState::Listening | PortState::Passive => Ok(()),
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
