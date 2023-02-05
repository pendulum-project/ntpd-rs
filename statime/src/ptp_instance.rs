use arrayvec::ArrayVec;

use crate::datastructures::common::PortIdentity;
use crate::datastructures::datasets::{
    CurrentDS, DefaultDS, DelayMechanism, ParentDS, PortDS, TimePropertiesDS,
};
use crate::network::NetworkPort;
use crate::{
    clock::{Clock, Watch},
    filters::Filter,
    network::{NetworkPacket, NetworkRuntime},
    port::Port,
    time::{Duration, Instant},
};

const MAX_PORTS: usize = 20;

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the `handle_*` methods whenever required.
pub struct PtpInstance<P, C, W, F> {
    default_ds: DefaultDS,
    current_ds: Option<CurrentDS>,
    parent_ds: Option<ParentDS>,
    time_properties_ds: TimePropertiesDS,
    ports: ArrayVec<Port<P, W>, MAX_PORTS>,
    local_clock: C,
    filter: F,
}

impl<P, C, W, F> PtpInstance<P, C, W, F> {
    /// Create a new instance
    ///
    /// - `config`: The configuration of the ptp instance
    /// - `runtime`: The network runtime with which sockets can be opened
    /// - `clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    pub fn new(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        local_clock: C,
        filter: F,
    ) -> Self {
        PtpInstance {
            default_ds,
            current_ds: None,
            parent_ds: None,
            time_properties_ds,
            ports: ArrayVec::new(),
            local_clock,
            filter,
        }
    }
}

impl<P, C: Clock, F> PtpInstance<P, C, C::Watch, F> {
    pub fn with_port<NR>(
        mut self,
        log_min_delay_req_interval: i8,
        log_announce_interval: i8,
        announce_receipt_timeout: u8,
        log_sync_interval: i8,
        delay_mechanism: DelayMechanism,
        log_min_p_delay_req_interval: i8,
        version_number: u8,
        minor_version_number: u8,

        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
    ) -> Self
    where
        NR: NetworkRuntime<PortType = P>,
    {
        let port_number = self.ports.len() as u16 + 1;
        let port_identity = PortIdentity {
            clock_identity: self.default_ds.clock_identity,
            port_number,
        };
        let port_ds = PortDS::new(
            port_identity,
            log_min_delay_req_interval,
            log_announce_interval,
            announce_receipt_timeout,
            log_sync_interval,
            delay_mechanism,
            log_min_p_delay_req_interval,
            version_number,
            minor_version_number,
        );

        // We always need a loop for the BMCA, so we create a watch immediately and set the alarm
        let mut bmca_watch = self.local_clock.get_watch();
        bmca_watch.set_alarm(Duration::from_log_interval(log_announce_interval));

        // Set the announce receipt timeout
        let mut announce_timeout_watch = self.local_clock.get_watch();
        announce_timeout_watch.set_alarm(Duration::from_log_interval(
            announce_receipt_timeout as i8 * log_announce_interval,
        ));

        let announce_watch = self.local_clock.get_watch();
        let sync_watch = self.local_clock.get_watch();

        let port = Port::new(
            port_ds,
            runtime,
            interface,
            bmca_watch,
            announce_timeout_watch,
            announce_watch,
            sync_watch,
        );
        self.ports.push(port);
        self
    }
}

impl<P: NetworkPort, C: Clock, W: Watch, F: Filter> PtpInstance<P, C, W, F> {
    /// Let the instance handle a received network packet.
    ///
    /// This should be called for any and all packets that were received on the opened sockets of the network runtime.
    pub fn handle_network(&mut self, packet: &NetworkPacket) {
        for port in &mut self.ports {
            port.handle_network(packet, port.bmca_watch.now(), &self.default_ds);

            // TODO: Verify this is desired behavior
            if let Ok(data) = port.extract_measurement() {
                let (offset, freq_corr) = self.filter.absorb(data);
                self.local_clock
                    .adjust(offset, freq_corr, &self.time_properties_ds)
                    .expect("Unexpected error adjusting clock");
            }
        }
    }
}

impl<P: NetworkPort, C, W: Watch, F> PtpInstance<P, C, W, F> {
    /// Let the instance know what the TX or send timestamp was of a packet that was recently sent.
    ///
    /// When sending a time critical message we need to know exactly when it was sent to do all of the arithmetic.
    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: Instant) {
        for port in &mut self.ports {
            port.handle_send_timestamp(id, timestamp);
        }
    }
}

impl<P: NetworkPort, C: Clock, F> PtpInstance<P, C, C::Watch, F> {
    /// When a watch alarm goes off, this function must be called with the id of the watch.
    /// There is no strict timing requirement, but it should not be called before the alarm time and should not be called
    /// more than 10ms after the alarm time.
    pub fn handle_alarm(&mut self, id: <<C as Clock>::Watch as Watch>::WatchId) {
        todo!("solve with async");
        for port in &mut self.ports {
            if id == port.bmca_watch.id() {
                // The bmca watch triggered, we must run the bmca
                // But first set a new alarm
                port.bmca_watch.set_alarm(port.announce_interval());

                let current_time = self.local_clock.now();
                let erbest = port
                    .take_best_port_announce_message(current_time)
                    .map(|v| (v.0, v.2));
                let erbest = erbest
                    .as_ref()
                    .map(|(message, identity)| (message, identity));

                // Run the state decision
                port.perform_state_decision(
                    erbest,
                    erbest,
                    &self.default_ds,
                    &mut self.time_properties_ds,
                );
            } else {
                // TODO: what to do when we have multiple ports?
                let current_time = self.local_clock.now();
                port.handle_alarm(id, current_time, &self.default_ds);
            }
        }
    }
}
