use arrayvec::ArrayVec;
use std::cell::RefCell;
use std::convert::Infallible;

use crate::clock::{Clock, Timer};
use crate::datastructures::common::{PortIdentity, Timestamp};
use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, PortDS, TimePropertiesDS};
use crate::datastructures::messages::AnnounceMessage;
use crate::filters::Filter;
use crate::network::NetworkPort;
use crate::network::NetworkRuntime;
use crate::port::Port;

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the `handle_*` methods whenever required.
pub struct PtpInstance<P, C, F, const N: usize> {
    default_ds: DefaultDS,
    current_ds: Option<CurrentDS>,
    parent_ds: Option<ParentDS>,
    time_properties_ds: RefCell<TimePropertiesDS>,
    // TODO: Might as well be an array
    ports: ArrayVec<Port<P>, N>,
    local_clock: RefCell<C>,
    filter: RefCell<F>,
    announce_messages: RefCell<[Option<(AnnounceMessage, Timestamp, PortIdentity)>; N]>,
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
            time_properties_ds: RefCell::new(time_properties_ds),
            ports: ArrayVec::new(),
            local_clock: RefCell::new(local_clock),
            filter: RefCell::new(filter),
            announce_messages: RefCell::new([None; 1]),
        }
        .with_port(port_ds, runtime, interface)
        .await
    }
}

impl<P, C: Clock, F, const N: usize> PtpInstance<P, C, F, N> {
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
            time_properties_ds: RefCell::new(time_properties_ds),
            ports: ArrayVec::new(),
            local_clock: RefCell::new(local_clock),
            filter: RefCell::new(filter),
            announce_messages: RefCell::new([None; N]),
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
    pub async fn run(&mut self, timer: &impl Timer) -> [Infallible; N] {
        log::info!("Running!");

        let mut run_ports = self.ports.iter_mut().map(|port| {
            port.run_port(
                timer,
                &self.local_clock,
                &self.filter,
                &self.default_ds,
                &self.time_properties_ds,
                &self.announce_messages,
            )
        });
        let futures = [(); N].map(|_| run_ports.next().expect("not all ports were initialized"));

        embassy_futures::join::join_array(futures).await
    }
}
