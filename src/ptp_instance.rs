use crate::{
    datastructures::common::ClockIdentity,
    network::{NetworkPacket, NetworkRuntime},
    port::Port,
    time::OffsetTime,
};

pub struct Config<NR: NetworkRuntime> {
    pub identity: ClockIdentity,
    pub sdo: u16,
    pub domain: u8,
    pub interface: NR::InterfaceDescriptor,
}

pub struct PtpInstance<NR: NetworkRuntime> {
    port: Port<NR>,
}

impl<NR: NetworkRuntime> PtpInstance<NR> {
    pub fn new(config: Config<NR>, runtime: NR) -> Self {
        PtpInstance {
            port: Port::new(
                config.identity,
                0,
                config.sdo,
                config.domain,
                runtime.clone(),
                config.interface,
            ),
        }
    }

    pub fn handle_network(&mut self, packet: NetworkPacket) {
        self.port.handle_network(packet);
        if let Some(data) = self.port.extract_measurement() {
            println!("Offset to master: {}", data);
        }
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) {
        self.port.handle_send_timestamp(id, timestamp);
    }
}
