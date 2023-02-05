use crate::datastructures::WireFormatError;
use crate::port::state::SlaveError;

pub type Result<T, E = PortError> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum PortError {
    WireFormat(WireFormatError),
    Slave(SlaveError),
    InvalidState,
    UnexpectedMessage,
}

impl From<WireFormatError> for PortError {
    fn from(value: WireFormatError) -> Self {
        PortError::WireFormat(value)
    }
}

impl From<SlaveError> for PortError {
    fn from(value: SlaveError) -> Self {
        PortError::Slave(value)
    }
}
