use std::cell::RefCell;
use std::convert::Infallible;
use std::pin::{pin, Pin};

use crate::bmc::bmca::Bmca;
use crate::clock::{Clock, Timer};
use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS};
use crate::filters::Filter;
use crate::network::NetworkPort;
use crate::port::{Port, PortError, Ticker};

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the `handle_*` methods whenever required.
pub struct PtpInstance<P, C, F, const N: usize> {
    default_ds: DefaultDS,
    current_ds: Option<CurrentDS>,
    parent_ds: Option<ParentDS>,
    time_properties_ds: TimePropertiesDS,
    ports: [Port<P>; N],
    local_clock: RefCell<C>,
    filter: RefCell<F>,
}

impl<P, C, F> PtpInstance<P, C, F, 1> {
    /// Create a new instance
    ///
    /// - `local_clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    /// - `runtime`: The network runtime with which sockets can be opened
    pub fn new_ordinary_clock(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        port: Port<P>,
        local_clock: C,
        filter: F,
    ) -> Self {
        PtpInstance::new_boundary_clock(default_ds, time_properties_ds, [port], local_clock, filter)
    }
}

impl<P, C, F, const N: usize> PtpInstance<P, C, F, N> {
    /// Create a new instance
    ///
    /// - `config`: The configuration of the ptp instance
    /// - `clock`: The clock that will be adjusted and provides the watches
    /// - `filter`: A filter for time measurements because those are always a bit wrong and need some processing
    pub fn new_boundary_clock(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        ports: [Port<P>; N],
        local_clock: C,
        filter: F,
    ) -> Self {
        for (index, port) in ports.iter().enumerate() {
            assert_eq!(port.identity().port_number - 1, index as u16);
        }
        PtpInstance {
            default_ds,
            current_ds: None,
            parent_ds: None,
            time_properties_ds,
            ports,
            local_clock: RefCell::new(local_clock),
            filter: RefCell::new(filter),
        }
    }
}

impl<P: NetworkPort, C: Clock, F: Filter, const N: usize> PtpInstance<P, C, F, N> {
    pub async fn run(&mut self, timer: &impl Timer) -> [Infallible; N] {
        log::info!("Running!");

        let interval = self
            .ports
            .iter()
            .map(|port| port.announce_interval())
            .max()
            .expect("no ports");
        let mut bmca_timeout = pin!(Ticker::new(|interval| timer.after(interval), interval));

        let mut timeouts = self.ports.iter().map(|port| {
            let announce_receipt_timeout = Ticker::new(
                |interval| timer.after(interval),
                port.announce_receipt_interval(),
            );
            let sync_timeout = Ticker::new(|interval| timer.after(interval), port.sync_interval());
            let announce_timeout =
                Ticker::new(|interval| timer.after(interval), port.announce_interval());

            (announce_receipt_timeout, sync_timeout, announce_timeout)
        });
        let timeouts =
            pin!([(); N].map(|_| timeouts.next().expect("not all ports were initialized")));

        let mut pinned_timeouts = unsafe {
            timeouts.get_unchecked_mut().iter_mut().map(|(a, b, c)| {
                (
                    Pin::new_unchecked(a),
                    Pin::new_unchecked(b),
                    Pin::new_unchecked(c),
                )
            })
        };
        let mut pinned_timeouts = [(); N].map(|_| {
            pinned_timeouts
                .next()
                .expect("not all ports were initialized")
        });

        let mut run_ports = self.ports.iter_mut().zip(&mut pinned_timeouts).map(
            |(port, (announce_receipt_timeout, sync_timeout, announce_timeout))| {
                port.run_port(
                    &self.local_clock,
                    &self.filter,
                    announce_receipt_timeout,
                    sync_timeout,
                    announce_timeout,
                    &self.default_ds,
                    &self.time_properties_ds,
                )
            },
        );
        let mut run_ports = embassy_futures::join::join_array(
            [(); N].map(|_| run_ports.next().expect("not all ports were initialized")),
        );

        run_ports.await
    }

    fn run_bmca(&mut self) {
        let mut erbests = [None; N];

        let current_time = self
            .local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)
            .unwrap()
            .into();

        for (index, port) in self.ports.iter_mut().enumerate() {
            erbests[index] = port.best_local_announce_message(current_time);
        }

        // TODO: What to do with `None`s?
        let ebest = Bmca::find_best_announce_message(erbests.iter().flatten().cloned());

        for (index, port) in self.ports.iter_mut().enumerate() {
            let recommended_state = Bmca::calculate_recommended_state(
                &self.default_ds,
                ebest,
                erbests[index],
                port.state(),
            );

            if let Some(recommended_state) = recommended_state {
                if let Err(error) =
                    port.set_recommended_state(recommended_state, &mut self.time_properties_ds)
                {
                    log::error!("{:?}", error)
                }
            }
        }
    }
}
