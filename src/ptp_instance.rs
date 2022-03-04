use crate::{
    clock::{Clock, TimeProperties, Watch},
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

pub struct PtpInstance<NR: NetworkRuntime, C: Clock> {
    port: Port<NR>,
    clock: C,
}

impl<NR: NetworkRuntime, C: Clock> PtpInstance<NR, C> {
    pub fn new(config: Config<NR>, runtime: NR, clock: C) -> Self {
        PtpInstance {
            port: Port::new(
                config.identity,
                0,
                config.sdo,
                config.domain,
                runtime,
                config.interface,
            ),
            clock,
        }
    }

    pub fn handle_network(&mut self, packet: NetworkPacket) {
        self.port.handle_network(packet);
        if let Some(data) = self.port.extract_measurement() {
            self.clock
                .adjust(
                    data,
                    1.0,
                    TimeProperties::ArbitraryTime {
                        time_traceable: false,
                        frequency_traceable: false,
                    },
                )
                .expect("Unexpected error adjusting clock");
            println!("Offset to master: {}", data);
        }
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) {
        self.port.handle_send_timestamp(id, timestamp);
    }

    pub fn handle_alarm(&mut self, _id: <<C as Clock>::W as Watch>::WatchId) {}
}
