use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, PortDS, TimePropertiesDS};
use crate::network::NetworkPort;
use crate::{
    clock::{Clock, Watch},
    filters::Filter,
    network::{NetworkPacket, NetworkRuntime},
    port::Port,
    time::{Duration, Instant},
};

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the `handle_*` methods whenever required.
pub struct PtpInstance<P, C: Clock, F> {
    default_ds: DefaultDS,
    current_ds: Option<CurrentDS>,
    parent_ds: Option<ParentDS>,
    time_properties_ds: TimePropertiesDS,

    port: Port<P, C::Watch>,
    clock: C,
    bmca_watch: C::Watch,
    filter: F,
}

impl<P: NetworkPort, C: Clock, F: Filter> PtpInstance<P, C, F> {
    /// Create a new instance
    ///
    /// - `config`: The configuration of the ptp instance
    /// - `runtime`: The network runtime with which sockets can be opened
    /// - `clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    pub fn new<NR>(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        port_ds: PortDS,
        interface: NR::InterfaceDescriptor,
        runtime: NR,
        mut clock: C,
        filter: F,
    ) -> Self
    where
        NR: NetworkRuntime<PortType = P>,
    {
        // We always need a loop for the BMCA, so we create a watch immediately and set the alarm
        let mut bmca_watch = clock.get_watch();
        bmca_watch.set_alarm(Duration::from_log_interval(port_ds.log_announce_interval));

        // Set the announce receipt timeout
        // TODO: what to do when we have multiple ports?
        let mut announce_timeout_watch = clock.get_watch();
        announce_timeout_watch.set_alarm(Duration::from_log_interval(
            port_ds.announce_receipt_timeout as i8 * port_ds.log_announce_interval,
        ));

        let announce_watch = clock.get_watch();
        let sync_watch = clock.get_watch();

        PtpInstance {
            default_ds,
            current_ds: None,
            parent_ds: None,
            time_properties_ds,
            port: Port::new(
                port_ds,
                runtime,
                interface,
                announce_timeout_watch,
                announce_watch,
                sync_watch,
            ),
            clock,
            bmca_watch,
            filter,
        }
    }

    /// Let the instance handle a received network packet.
    ///
    /// This should be called for any and all packets that were received on the opened sockets of the network runtime.
    pub fn handle_network(&mut self, packet: NetworkPacket) {
        self.port
            .handle_network(packet, self.bmca_watch.now(), &self.default_ds);
        if let Some(data) = self.port.extract_measurement() {
            let (offset, freq_corr) = self.filter.absorb(data);
            self.clock
                .adjust(offset, freq_corr, &self.time_properties_ds)
                .expect("Unexpected error adjusting clock");
        }
    }

    /// Let the instance know what the TX or send timestamp was of a packet that was recently sent.
    ///
    /// When sending a time critical message we need to know exactly when it was sent to do all of the arithmetic.
    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: Instant) {
        self.port.handle_send_timestamp(id, timestamp);
    }

    /// When a watch alarm goes off, this function must be called with the id of the watch.
    /// There is no strict timing requirement, but it should not be called before the alarm time and should not be called
    /// more than 10ms after the alarm time.
    pub fn handle_alarm(&mut self, id: <<C as Clock>::Watch as Watch>::WatchId) {
        if id == self.bmca_watch.id() {
            // The bmca watch triggered, we must run the bmca
            // But first set a new alarm
            self.bmca_watch
                .set_alarm(self.port.get_log_announce_interval());

            // Currently we only have one port, so erbest is also automatically our ebest
            let current_time = self.clock.now();
            let erbest = self
                .port
                .take_best_port_announce_message(current_time)
                .map(|v| (v.0, v.2));
            let erbest = erbest
                .as_ref()
                .map(|(message, identity)| (message, identity));

            // Run the state decision
            self.port.perform_state_decision(
                erbest,
                erbest,
                &self.default_ds,
                &mut self.time_properties_ds,
            );
        } else {
            // TODO: what to do when we have multiple ports?
            let current_time = self.clock.now();
            self.port.handle_alarm(id, current_time, &self.default_ds);
        }
    }
}
