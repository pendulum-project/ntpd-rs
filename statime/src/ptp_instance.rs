use arrayvec::ArrayVec;

use crate::clock::{Clock, Timer};
use crate::datastructures::common::PortIdentity;
use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, PortDS, TimePropertiesDS};
use crate::filters::Filter;
use crate::network::NetworkPort;
use crate::network::NetworkRuntime;
use crate::port::Port;
use crate::time::Duration;
use futures::pin_mut;

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the `handle_*` methods whenever required.
pub struct PtpInstance<P, C, F, const N: usize> {
    default_ds: DefaultDS,
    current_ds: Option<CurrentDS>,
    parent_ds: Option<ParentDS>,
    time_properties_ds: TimePropertiesDS,
    ports: ArrayVec<Port<P>, N>,
    local_clock: C,
    filter: F,
}

impl<P, C: Clock, F> PtpInstance<P, C, F, 1> {
    /// Create a new instance
    ///
    /// - `local_clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    /// - `runtime`: The network runtime with which sockets can be opened
    pub async fn new_ordinary_clock<NR>(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        local_clock: C,
        filter: F,
        port_ds: PortDS,
        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
    ) -> Self
    where
        NR: NetworkRuntime<NetworkPort = P>,
    {
        assert_eq!(
            port_ds.port_identity,
            PortIdentity {
                clock_identity: default_ds.clock_identity,
                port_number: 1,
            }
        );

        PtpInstance {
            default_ds,
            current_ds: None,
            parent_ds: None,
            time_properties_ds,
            ports: ArrayVec::new(),
            local_clock,
            filter,
        }
        .with_port(port_ds, runtime, interface)
        .await
    }

    /// Create a new instance
    ///
    /// - `config`: The configuration of the ptp instance
    /// - `clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    pub async fn new_boundary_clock(
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

    pub async fn with_port<NR>(
        mut self,
        port_ds: PortDS,
        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
    ) -> Self
    where
        NR: NetworkRuntime<NetworkPort = P>,
    {
        assert_eq!(
            port_ds.port_identity,
            PortIdentity {
                clock_identity: self.default_ds.clock_identity,
                port_number: self.ports.len() as u16 + 1,
            }
        );

        let port = Port::new(port_ds, runtime, interface).await;
        self.ports.push(port);
        self
    }
}

impl<P: NetworkPort, C: Clock, F: Filter, const N: usize> PtpInstance<P, C, F, N> {
    // /// Let the instance handle a received network packet.
    // ///
    // /// This should be called for any and all packets that were received on the opened sockets of the network runtime.
    // pub fn handle_network(&mut self, packet: &NetworkPacket) {
    //     for port in &mut self.ports {
    //         port.handle_network(packet, port.bmca_watch.now(), &self.default_ds);
    //
    //         // TODO: Verify this is desired behavior
    //         if let Ok(data) = port.extract_measurement() {
    //             let (offset, freq_corr) = self.filter.absorb(data);
    //             self.local_clock
    //                 .adjust(offset, freq_corr, &self.time_properties_ds)
    //                 .expect("Unexpected error adjusting clock");
    //         }
    //     }
    // }

    pub async fn run(&mut self, timer: &impl Timer) -> ! {
        log::info!("Running!");

        // TODO: Move this to port?
        let bmca_timeout = timer.after(Duration::from_secs(1));
        pin_mut!(bmca_timeout);

        loop {
            // TODO: Change to support multiple ports
            for port in &mut self.ports {
                let current_time = self.local_clock.now();
                let run_port = port.run_port(current_time, &self.default_ds);

                match embassy_futures::select::select(&mut bmca_timeout, run_port).await {
                    embassy_futures::select::Either::First(_) => {
                        self.run_bmca();
                        bmca_timeout.set(timer.after(Duration::from_secs(1)));
                    }
                    embassy_futures::select::Either::Second(data) => {
                        let (offset, freq_corr) = self.filter.absorb(data);
                        self.local_clock
                            .adjust(offset, freq_corr, &self.time_properties_ds)
                            .expect("Unexpected error adjusting clock");
                    }
                }
            }
        }
    }

    fn run_bmca(&mut self) {
        // TODO: Change to support multiple ports
        for port in &mut self.ports {
            // Currently we only have one port, so erbest is also automatically our ebest
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
        }
    }
}
