use std::fmt::{Display, Formatter};

pub use master::MasterState;
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
    #[default]
    Initializing,
    Faulty,
    Disabled,
    Listening,
    PreMaster,
    Master(MasterState),
    Passive,
    Uncalibrated,
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
            PortState::Listening => Ok(()),
            PortState::Master(master) => {
                master
                    .handle_message(message, current_time, network_port, port_identity)
                    .await
            }
            PortState::Slave(slave) => {
                slave
                    .handle_message(message, current_time, network_port, port_identity)
                    .await?;
                Ok(())
            }
            _ => unimplemented!(),
        }
    }

    // TODO: Necessary?
    fn code(&self) -> u8 {
        match self {
            PortState::Initializing => 0x01,
            PortState::Faulty => 0x02,
            PortState::Disabled => 0x03,
            PortState::Listening => 0x04,
            PortState::PreMaster => 0x05,
            PortState::Master(_) => 0x06,
            PortState::Passive => 0x07,
            PortState::Uncalibrated => 0x08,
            PortState::Slave(_) => 0x09,
        }
    }
}

impl Display for PortState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Initializing => write!(f, "Initializing"),
            PortState::Faulty => write!(f, "Faulty"),
            PortState::Disabled => write!(f, "Disabled"),
            PortState::Listening => write!(f, "Listening"),
            PortState::PreMaster => write!(f, "Pre-Master"),
            PortState::Master(_) => write!(f, "Master"),
            PortState::Passive => write!(f, "Passive"),
            PortState::Uncalibrated => write!(f, "Uncalibrated"),
            PortState::Slave(_) => write!(f, "Slave"),
        }
    }
}
