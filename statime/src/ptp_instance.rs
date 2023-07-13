use core::{
    cell::RefCell,
    pin::{pin, Pin},
};

use futures::StreamExt;

use crate::{
    bmc::bmca::Bmca,
    clock::{Clock, Timer},
    datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
    filters::Filter,
    network::NetworkPort,
    port::{InBmca, Port, Startup, Ticker},
    utils::SignalContext,
};

/// A PTP node.
///
/// This object handles the complete running of the PTP protocol once created.
/// It provides all the logic for both ordinary and boundary clock mode.
///
/// # Example
/// Assuming we already have a network runtime and clock runtime, an ordinary
/// clock can be run by first creating all the datasets, then creating the port,
/// then finally setting up the instance and starting it:
///
/// ```ignore
/// let default_ds = DefaultDS::new_ordinary_clock(
///     clock_identity,
///     128,
///     128,
///     0,
///     false,
///     SdoId::new(0).unwrap(),
/// );
/// let time_properties_ds =
/// TimePropertiesDS::new_arbitrary_time(false, false, TimeSource::InternalOscillator);
/// let port_ds = PortDS::new(
///     PortIdentity {
///         clock_identity,
///         port_number: 1,
///     },
///     1,
///     1,
///     3,
///     0,
///     DelayMechanism::E2E,
///     1,
/// );
/// let port = Port::new(port_ds, &mut network_runtime, interface_name).await;
/// let mut instance = PtpInstance::new_ordinary_clock(
///     default_ds,
///     time_properties_ds,
///     port,
///     local_clock,
///     BasicFilter::new(0.25),
/// );
///
/// instance.run(&TimerImpl).await;
/// ```
pub struct PtpInstance<P, C, F, const N: usize> {
    ports: [Port<Startup<P>>; N],
    state: RefCell<PtpInstanceState<C, F>>,
}

pub(crate) struct PtpInstanceState<C, F> {
    pub(crate) default_ds: DefaultDS,
    pub(crate) current_ds: CurrentDS,
    pub(crate) parent_ds: ParentDS,
    pub(crate) time_properties_ds: TimePropertiesDS,
    pub(crate) local_clock: RefCell<C>,
    pub(crate) filter: RefCell<F>,
}

// START NEW INTERFACE
impl<C: Clock, F> PtpInstanceState<C, F> {
    pub fn bmca(&mut self, ports: &mut [&mut Port<InBmca<'_, C, F>>]) {
        let current_time = self.local_clock.get_mut().now().into();

        for port in ports.iter_mut() {
            port.calculate_best_local_announce_message(current_time)
        }

        let ebest = Bmca::find_best_announce_message(
            ports
                .iter()
                .filter_map(|port| port.best_local_announce_message()),
        );

        for port in ports.iter_mut() {
            let recommended_state = Bmca::calculate_recommended_state(
                &self.default_ds,
                ebest,
                port.best_local_announce_message(),
                port.state(),
            );

            log::debug!(
                "Recommended state port {}: {:?}",
                port.number(),
                recommended_state
            );

            if let Some(recommended_state) = recommended_state {
                let PtpInstanceState {
                    ref mut time_properties_ds,
                    ref mut current_ds,
                    ref mut parent_ds,
                    ..
                } = *self;
                if let Err(error) = port.set_recommended_state(
                    recommended_state,
                    time_properties_ds,
                    current_ds,
                    parent_ds,
                ) {
                    log::error!("{:?}", error)
                }
            }
        }
    }

    #[allow(unused)]
    pub fn bmca_interval(&self) -> std::time::Duration {
        todo!()
    }
}
// END NEW INTERFACE

impl<P, C, F> PtpInstance<P, C, F, 1> {
    /// Create a new ordinary clock instance.
    ///
    /// This creates a PTP ordinary clock with a single port. Note that the port
    /// identity of the provided port needs to have a port number of 1.
    pub fn new_ordinary_clock(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        port: Port<Startup<P>>,
        local_clock: C,
        filter: F,
    ) -> Self {
        PtpInstance::new_boundary_clock(default_ds, time_properties_ds, [port], local_clock, filter)
    }
}

impl<P, C, F, const N: usize> PtpInstance<P, C, F, N> {
    /// Create a new boundary clock instance.
    ///
    /// This creates a PTP boundary clock. Multiple ports can be provided to
    /// handle multiple network interfaces. For each provided port, the port
    /// number needs to equal the index of the port in the array plus 1.
    pub fn new_boundary_clock(
        default_ds: DefaultDS,
        time_properties_ds: TimePropertiesDS,
        ports: [Port<Startup<P>>; N],
        local_clock: C,
        filter: F,
    ) -> Self {
        for (index, port) in ports.iter().enumerate() {
            assert_eq!(port.identity().port_number - 1, index as u16);
        }
        PtpInstance {
            ports,
            state: RefCell::new(PtpInstanceState {
                default_ds,
                current_ds: Default::default(),
                parent_ds: ParentDS::new(default_ds),
                time_properties_ds,
                local_clock: RefCell::new(local_clock),
                filter: RefCell::new(filter),
            }),
        }
    }
}

impl<P: NetworkPort, C: Clock, F: Filter, const N: usize> PtpInstance<P, C, F, N> {
    /// Run the PTP stack.
    ///
    /// This future needs to be awaited for the PTP protocol to be handled and
    /// the clock to be synchronized.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run(self, timer: &impl Timer) -> ! {
        log::info!("Running!");

        let interval = self
            .ports
            .iter()
            .map(|port| port.announce_interval())
            .max()
            .expect("no ports");
        let mut bmca_timeout = pin!(Ticker::new(|interval| timer.after(interval), interval));

        let announce_receipt_timeouts = pin!(into_array::<_, N>(self.ports.iter().map(|port| {
            Ticker::new(
                |interval| timer.after(interval),
                port.announce_receipt_interval(),
            )
        })));
        let sync_timeouts = pin!(into_array::<_, N>(self.ports.iter().map(|port| {
            Ticker::new(|interval| timer.after(interval), port.sync_interval())
        })));
        let announce_timeouts = pin!(into_array::<_, N>(self.ports.iter().map(|port| {
            Ticker::new(|interval| timer.after(interval), port.announce_interval())
        })));

        let mut pinned_announce_receipt_timeouts = into_array::<_, N>(unsafe {
            announce_receipt_timeouts
                .get_unchecked_mut()
                .iter_mut()
                .map(|announce_receipt_timeout| Pin::new_unchecked(announce_receipt_timeout))
        });
        let mut pinned_sync_timeouts = into_array::<_, N>(unsafe {
            sync_timeouts
                .get_unchecked_mut()
                .iter_mut()
                .map(|sync_timeout| Pin::new_unchecked(sync_timeout))
        });
        let mut pinned_announce_timeouts = into_array::<_, N>(unsafe {
            announce_timeouts
                .get_unchecked_mut()
                .iter_mut()
                .map(|announce_timeout| Pin::new_unchecked(announce_timeout))
        });

        let mut stopcontexts = [(); N].map(|_| SignalContext::new());

        let PtpInstance { ports, state } = self;

        let mut ports_split = ports.map(|port| {
            let (port, network_port) = port.into_running(&state);
            (port, Some(network_port))
        });
        let mut network_ports =
            core::array::from_fn::<_, N, _>(|i| ports_split[i].1.take().unwrap());
        let mut ports = ports_split.map(|(port, _)| port);

        loop {
            let mut iter = stopcontexts.iter_mut();
            let stopperpairs =
                core::array::from_fn::<_, N, _>(move |_| iter.next().unwrap().signal());
            let signallers = core::array::from_fn::<_, N, _>(|i| stopperpairs[i].1.clone());
            let signals = stopperpairs.map(|v| v.0);

            let mut run_ports = ports
                .iter_mut()
                .zip(&mut pinned_announce_receipt_timeouts)
                .zip(&mut pinned_sync_timeouts)
                .zip(&mut pinned_announce_timeouts)
                .zip(signals)
                .zip(&mut network_ports)
                .map(
                    |(
                        (
                            (((port, announce_receipt_timeout), sync_timeout), announce_timeout),
                            stop,
                        ),
                        network_port,
                    )| {
                        port.run_port(
                            network_port,
                            announce_receipt_timeout,
                            sync_timeout,
                            announce_timeout,
                            stop,
                        )
                    },
                );
            let run_ports =
                embassy_futures::join::join_array([(); N].map(|_| run_ports.next().unwrap()));

            embassy_futures::join::join(
                async {
                    bmca_timeout.next().await;
                    log::trace!("Signalling bmca");
                    signallers.map(|v| v.raise());
                },
                run_ports,
            )
            .await;

            let mut bmca_ports = ports.map(|port| port.start_bmca());

            // this can be simplified once array::each_mut stabilizes (https://github.com/rust-lang/rust/issues/76118)
            let mut bmca_ports_iter = bmca_ports.iter_mut();
            state
                .borrow_mut()
                .bmca(&mut core::array::from_fn::<_, N, _>(|_| {
                    bmca_ports_iter.next().unwrap()
                }));

            // Ignoring the actions here isn't great but won't fundamentally break the
            // futures since they still use periodic timers that don't require
            // manual resetting.
            ports = bmca_ports.map(|port| port.end_bmca().0);
        }
    }
}

fn into_array<T, const N: usize>(iter: impl IntoIterator<Item = T>) -> [T; N] {
    let mut iter = iter.into_iter();
    let arr = [(); N].map(|_| iter.next().expect("not enough elements"));
    assert!(iter.next().is_none());
    arr
}
