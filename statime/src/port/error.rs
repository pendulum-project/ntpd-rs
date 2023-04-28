use crate::{
    datastructures::WireFormatError,
    port::state::{MasterError, SlaveError},
};

pub type Result<T, E = PortError> = core::result::Result<T, E>;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum PortError {
    #[cfg_attr(feature = "std", error("failed to retrieve local clock"))]
    ClockBusy,
    #[cfg_attr(feature = "std", error("failed to retrieve filter"))]
    FilterBusy,
    #[cfg_attr(feature = "std", error("something went wrong on the network"))]
    Network,
    #[cfg_attr(feature = "std", error("wire format error: {0}"))]
    WireFormat(WireFormatError),
    #[cfg_attr(feature = "std", error("slave error: {0}"))]
    Slave(SlaveError),
    #[cfg_attr(feature = "std", error("master error: {0}"))]
    Master(MasterError),
}

impl From<WireFormatError> for PortError {
    fn from(v: WireFormatError) -> Self {
        Self::WireFormat(v)
    }
}

impl From<SlaveError> for PortError {
    fn from(v: SlaveError) -> Self {
        Self::Slave(v)
    }
}

impl From<MasterError> for PortError {
    fn from(v: MasterError) -> Self {
        Self::Master(v)
    }
}
