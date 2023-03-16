use thiserror::Error;

use crate::datastructures::WireFormatError;
use crate::port::state::{MasterError, SlaveError};

pub type Result<T, E = PortError> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum PortError {
    #[error("failed to retrieve local clock")]
    ClockBusy,
    #[error("failed to retrieve filter")]
    FilterBusy,
    #[error("something went wrong on the network")]
    Network,
    #[error("wire format error: {0}")]
    WireFormat(#[from] WireFormatError),
    #[error("slave error: {0}")]
    Slave(#[from] SlaveError),
    #[error("master error: {0}")]
    Master(#[from] MasterError),
}
