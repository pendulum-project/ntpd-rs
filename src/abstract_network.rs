use crate::time::OffsetTime;

pub trait NetworkRuntime {
    type InterfaceName: Clone;
    type PortType: NetworkPort;
    fn open(&self, interface: Self::InterfaceName, time_critical: bool) -> Self::PortType;
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
