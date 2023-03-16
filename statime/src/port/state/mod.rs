use std::fmt::{Display, Formatter};

pub use master::{MasterError, MasterState};
pub use slave::{SlaveError, SlaveState};

use crate::datastructures::common::PortIdentity;
use crate::datastructures::messages::Message;
use crate::network::NetworkPort;
use crate::port::error::Result;
use crate::time::Instant;

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
    pub async fn handle_message(
        &mut self,
        message: Message,
        current_time: Instant,
        network_port: &mut impl NetworkPort,
        port_identity: PortIdentity,
    ) -> Result<()> {
        match self {
            PortState::Master(master) => {
                master
                    .handle_message(message, current_time, network_port, port_identity)
                    .await?;
                Ok(())
            }
            PortState::Slave(slave) => {
                slave
                    .handle_message(message, current_time, network_port, port_identity)
                    .await?;
                Ok(())
            }
            PortState::Listening | PortState::Disabled | PortState::Passive => Ok(()),
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
