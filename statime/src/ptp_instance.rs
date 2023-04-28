use core::{
    cell::RefCell,
    future::Future,
    pin::{pin, Pin},
};

use futures::StreamExt;

use crate::{
    bmc::bmca::Bmca,
    clock::{Clock, Timer},
    datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
    filters::Filter,
    network::NetworkPort,
    port::{Port, PortError, Ticker},
    time::Duration,
    utils::SignalContext,
};

/// Object that acts as the central point of this library.
/// It is the main instance of the running protocol.
///
/// The instance doesn't run on its own, but requires the user to invoke the
/// `handle_*` methods whenever required.
pub struct PtpInstance<P, C, F, const N: usize> {
    default_ds: DefaultDS,
    current_ds: CurrentDS,
    parent_ds: ParentDS,
    time_properties_ds: TimePropertiesDS,
    ports: [Port<P>; N],
    local_clock: RefCell<C>,
    filter: RefCell<F>,
}

impl<P, C, F> PtpInstance<P, C, F, 1> {
    /// Create a new instance
    ///
    /// - `local_clock`: The clock that will be adjusted and provides the
    ///   watches
    /// - `filter`: A filter for time measurements because those are always a
    ///   bit wrong and need some processing
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
    /// - `filter`: A filter for time measurements because those are always a
    ///   bit wrong and need some processing
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
            current_ds: Default::default(),
            parent_ds: Default::default(),
            time_properties_ds,
            ports,
            local_clock: RefCell::new(local_clock),
            filter: RefCell::new(filter),
        }
    }
}

impl<P: NetworkPort, C: Clock, F: Filter, const N: usize> PtpInstance<P, C, F, N> {
    pub async fn run(&mut self, timer: &impl Timer) -> ! {
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

        loop {
            let mut iter = stopcontexts.iter_mut();
            let stopperpairs =
                core::array::from_fn::<_, N, _>(move |_| iter.next().unwrap().signal());
            let signallers = core::array::from_fn::<_, N, _>(|i| stopperpairs[i].1.clone());
            let signals = stopperpairs.map(|v| v.0);

            let mut run_ports = self
                .ports
                .iter_mut()
                .zip(&mut pinned_announce_receipt_timeouts)
                .zip(&mut pinned_sync_timeouts)
                .zip(&mut pinned_announce_timeouts)
                .zip(signals.into_iter())
                .map(
                    |(
                        (((port, announce_receipt_timeout), sync_timeout), announce_timeout),
                        stop,
                    )| {
                        port.run_port(
                            &self.local_clock,
                            &self.filter,
                            announce_receipt_timeout,
                            sync_timeout,
                            announce_timeout,
                            &self.default_ds,
                            &self.time_properties_ds,
                            &self.parent_ds,
                            &self.current_ds,
                            stop,
                        )
                    },
                );
            let run_ports =
                embassy_futures::join::join_array([(); N].map(|_| run_ports.next().unwrap()));

            embassy_futures::join::join(
                async {
                    bmca_timeout.next().await;
                    signallers.map(|v| v.raise());
                },
                run_ports,
            )
            .await;

            self.run_bmca(&mut pinned_announce_receipt_timeouts);
        }
    }

    fn run_bmca<Fut: Future>(
        &mut self,
        pinned_timeouts: &mut [Pin<&mut Ticker<Fut, impl FnMut(Duration) -> Fut>>],
    ) {
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
                if let Err(error) = port.set_recommended_state(
                    recommended_state,
                    &mut pinned_timeouts[index],
                    &mut self.time_properties_ds,
                    &mut self.current_ds,
                    &mut self.parent_ds,
                ) {
                    log::error!("{:?}", error)
                }
            }
        }
    }
}

fn into_array<T, const N: usize>(iter: impl IntoIterator<Item = T>) -> [T; N] {
    let mut iter = iter.into_iter();
    let arr = [(); N].map(|_| iter.next().expect("not enough elements"));
    assert!(iter.next().is_none());
    arr
}
