use core::sync::atomic::{AtomicI8, Ordering};

use atomic_refcell::AtomicRefCell;
use rand::Rng;

use crate::{
    bmc::bmca::Bmca,
    clock::Clock,
    config::InstanceConfig,
    datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
    port::{InBmca, Port},
    PortConfig, PortIdentity,
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
pub struct PtpInstance<C, F> {
    state: AtomicRefCell<PtpInstanceState<C, F>>,
    log_bmca_interval: AtomicI8,
}

#[derive(Debug)]
pub(crate) struct PtpInstanceState<C, F> {
    pub(crate) default_ds: DefaultDS,
    pub(crate) current_ds: CurrentDS,
    pub(crate) parent_ds: ParentDS,
    pub(crate) time_properties_ds: TimePropertiesDS,
    pub(crate) local_clock: AtomicRefCell<C>,
    pub(crate) filter: AtomicRefCell<F>,
}

impl<C: Clock, F> PtpInstanceState<C, F> {
    fn bmca<R: Rng>(&mut self, ports: &mut [&mut Port<InBmca<'_, C, F>, R>]) {
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
                if let Err(error) = port.set_recommended_state(
                    recommended_state,
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

impl<C: Clock, F> PtpInstance<C, F> {
    pub fn new(
        config: InstanceConfig,
        time_properties_ds: TimePropertiesDS,
        local_clock: C,
        filter: F,
    ) -> Self {
        let default_ds = DefaultDS::new(config);
        Self {
            state: AtomicRefCell::new(PtpInstanceState {
                default_ds,
                current_ds: Default::default(),
                parent_ds: ParentDS::new(default_ds),
                time_properties_ds,
                local_clock: AtomicRefCell::new(local_clock),
                filter: AtomicRefCell::new(filter),
            }),
            log_bmca_interval: AtomicI8::new(i8::MAX),
        }
    }

    /// Add and initialize this port
    ///
    /// We start in the BMCA state because that is convenient
    pub fn add_port<R: Rng>(&self, config: PortConfig, rng: R) -> Port<InBmca<'_, C, F>, R> {
        self.log_bmca_interval
            .fetch_min(config.announce_interval.as_log_2(), Ordering::Relaxed);
        let mut state = self.state.borrow_mut();
        let port_identity = PortIdentity {
            clock_identity: state.default_ds.clock_identity,
            port_number: state.default_ds.number_ports,
        };
        state.default_ds.number_ports += 1;
        Port::new(&self.state, config, port_identity, rng)
    }

    pub fn bmca<R: Rng>(&self, ports: &mut [&mut Port<InBmca<'_, C, F>, R>]) {
        self.state.borrow_mut().bmca(ports)
    }

    pub fn bmca_interval(&self) -> core::time::Duration {
        core::time::Duration::from_secs_f64(
            2f64.powi(self.log_bmca_interval.load(Ordering::Relaxed) as i32),
        )
    }
}
