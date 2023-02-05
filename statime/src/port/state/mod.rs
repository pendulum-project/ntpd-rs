pub use master::MasterState;
pub use slave::{SlaveError, SlaveState};

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
