use crate::time::OffsetTime;

trait NetworkRuntime {
    type InterfaceName;
    type PortType: NetworkPort;
    fn open(&self, interface: Self::InterfaceName, time_critical: bool) -> Self::PortType;
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub data: Vec<u8>,
    pub timestamp: Option<OffsetTime>,
}

trait NetworkPort {
    fn send(&mut self, data: &[u8]) -> Option<usize>;
    // Recv is implicit, works using events passed through function calls
    // Similarly for timestamps on sent messages.
}
