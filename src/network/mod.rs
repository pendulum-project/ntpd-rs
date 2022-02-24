pub mod linux;

use crate::time::OffsetTime;

// Todo
#[derive(Debug)]
pub struct NetworkError;

pub trait NetworkRuntime: Clone {
    type InterfaceDescriptor: Clone;
    type PortType: NetworkPort;
    type Error: std::error::Error + std::fmt::Display;

    fn open(
        &self,
        interface: Self::InterfaceDescriptor,
        time_critical: bool,
    ) -> Result<Self::PortType, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub data: Vec<u8>,
    pub timestamp: Option<OffsetTime>,
}

pub trait NetworkPort {
    fn send(&mut self, data: &[u8]) -> Option<usize>;
    // Recv is implicit, works using events passed through function calls
    // Similarly for timestamps on sent messages.
}
