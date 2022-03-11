use crate::{
    clock::{Clock, Watch},
    datastructures::common::ClockIdentity,
    network::{NetworkPacket, NetworkRuntime},
    port::{Port, PortConfig},
    time::{OffsetTime, TimeType},
};

pub struct Config<NR: NetworkRuntime> {
    pub identity: ClockIdentity,
    pub sdo: u16,
    pub domain: u8,
    pub interface: NR::InterfaceDescriptor,
    pub port_config: PortConfig,
}

pub struct PtpInstance<NR: NetworkRuntime, C: Clock> {
    port: Port<NR>,
    clock: C,
    bmca_watch: C::W,
}

impl<NR: NetworkRuntime, C: Clock> PtpInstance<NR, C> {
    pub fn new(config: Config<NR>, runtime: NR, mut clock: C) -> Self {
        let mut bmca_watch = clock.get_watch();

        bmca_watch.set_alarm(OffsetTime::from_log_interval(
            config.port_config.log_announce_interval,
        ));

        PtpInstance {
            port: Port::new(
                config.identity,
                0,
                config.sdo,
                config.domain,
                config.port_config,
                runtime,
                config.interface,
                clock.quality(),
            ),
            clock,
            bmca_watch,
        }
    }

    pub fn handle_network(&mut self, packet: NetworkPacket) {
        self.port.handle_network(packet, self.clock.now());
        if let Some((data, time_properties)) = self.port.extract_measurement() {
            self.clock
                .adjust(-data, 1.0, time_properties)
                .expect("Unexpected error adjusting clock");
            println!("Offset to master: {}", data);
        }
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: OffsetTime) {
        self.port.handle_send_timestamp(id, timestamp);
    }

    pub fn handle_alarm(&mut self, id: <<C as Clock>::W as Watch>::WatchId) {
        if id == self.bmca_watch.id() {
            // The bmca watch triggered, we must run the bmca
            // But first set a new alarm
            self.bmca_watch.set_alarm(self.port.get_announce_interval());

            // Currently we only have one port, so erbest is also automatically our ebest
            let current_time = self.clock.now();
            let erbest = self
                .port
                .take_best_port_announce_message(current_time)
                .map(|v| (v.0, v.2));
            let erbest = erbest
                .as_ref()
                .map(|(message, identity)| (message, identity));

            self.port.perform_state_decision(erbest, erbest);

            // Run the state decision
        }
    }
}
