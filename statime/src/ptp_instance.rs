use core::{
    marker::PhantomData,
    sync::atomic::{AtomicI8, Ordering},
};

use atomic_refcell::AtomicRefCell;
use rand::Rng;

use crate::{
    bmc::bmca::Bmca,
    clock::Clock,
    config::InstanceConfig,
    datastructures::{
        common::PortIdentity,
        datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
    },
    port::{InBmca, Port},
    Filter, PortConfig,
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
pub struct PtpInstance<F> {
    state: AtomicRefCell<PtpInstanceState>,
    log_bmca_interval: AtomicI8,
    _filter: PhantomData<F>,
}

#[derive(Debug)]
pub(crate) struct PtpInstanceState {
    pub(crate) default_ds: DefaultDS,
    pub(crate) current_ds: CurrentDS,
    pub(crate) parent_ds: ParentDS,
    pub(crate) time_properties_ds: TimePropertiesDS,
}

impl PtpInstanceState {
    fn bmca<C: Clock, F: Filter, R: Rng>(
        &mut self,
        ports: &mut [&mut Port<InBmca<'_>, R, C, F>],
        bmca_interval: crate::Duration,
    ) {
        debug_assert_eq!(self.default_ds.number_ports as usize, ports.len());

        for port in ports.iter_mut() {
            port.calculate_best_local_announce_message()
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
                port.best_local_announce_message(), // erbest
                port.state(),
            );

            log::debug!(
                "Recommended state port {}: {recommended_state:?}",
                port.number(),
            );

            if let Some(recommended_state) = recommended_state {
                port.set_recommended_state(
                    recommended_state,
                    &mut self.time_properties_ds,
                    &mut self.current_ds,
                    &mut self.parent_ds,
                    &self.default_ds,
                );
            }
        }

        // And update announce message ages
        for port in ports.iter_mut() {
            port.step_announce_age(bmca_interval);
        }
    }
}

impl<F> PtpInstance<F> {
    pub fn new(config: InstanceConfig, time_properties_ds: TimePropertiesDS) -> Self {
        let default_ds = DefaultDS::new(config);
        Self {
            state: AtomicRefCell::new(PtpInstanceState {
                default_ds,
                current_ds: Default::default(),
                parent_ds: ParentDS::new(default_ds),
                time_properties_ds,
            }),
            log_bmca_interval: AtomicI8::new(i8::MAX),
            _filter: PhantomData,
        }
    }
}

impl<F: Filter> PtpInstance<F> {
    /// Add and initialize this port
    ///
    /// We start in the BMCA state because that is convenient
    ///
    /// When providing the port with a different clock than the instance clock,
    /// the caller is responsible for propagating any property changes to this
    /// clock, and for synchronizing this clock with the instance clock as
    /// appropriate based on the ports state.
    pub fn add_port<C, R: Rng>(
        &self,
        config: PortConfig,
        filter_config: F::Config,
        clock: C,
        rng: R,
    ) -> Port<InBmca<'_>, R, C, F> {
        self.log_bmca_interval
            .fetch_min(config.announce_interval.as_log_2(), Ordering::Relaxed);
        let mut state = self.state.borrow_mut();
        let port_identity = PortIdentity {
            clock_identity: state.default_ds.clock_identity,
            port_number: state.default_ds.number_ports,
        };
        state.default_ds.number_ports += 1;
        Port::new(
            &self.state,
            config,
            filter_config,
            clock,
            port_identity,
            rng,
        )
    }

    pub fn bmca<C: Clock, R: Rng>(&self, ports: &mut [&mut Port<InBmca<'_>, R, C, F>]) {
        self.state.borrow_mut().bmca(
            ports,
            crate::Duration::from_seconds(
                2f64.powi(self.log_bmca_interval.load(Ordering::Relaxed) as i32),
            ),
        )
    }

    pub fn bmca_interval(&self) -> core::time::Duration {
        core::time::Duration::from_secs_f64(
            2f64.powi(self.log_bmca_interval.load(Ordering::Relaxed) as i32),
        )
    }
}
