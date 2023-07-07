use core::{cell::RefCell, future::Future, pin::Pin};

use embassy_futures::{select, select::Either3};
pub use error::{PortError, Result};
use futures::StreamExt;
pub use measurement::Measurement;
use state::{MasterState, PortState};
pub use ticker::Ticker;

use self::state::SlaveState;
use crate::{
    bmc::bmca::{BestAnnounceMessage, Bmca, RecommendedState},
    clock::Clock,
    config::PortConfig,
    datastructures::{
        common::{PortIdentity, TimeSource, WireTimestamp},
        datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
        messages::Message,
    },
    filters::Filter,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
    time::Duration,
    utils::Signal,
    Time,
};

mod error;
mod measurement;
mod sequence_id;
pub mod state;
#[cfg(test)]
mod tests;
mod ticker;

/// A single port of the PTP instance
///
/// One of these needs to be created per port of the PTP instance.
pub struct Port<P> {
    config: PortConfig,
    // Corresponds with PortDS port_state and enabled
    port_state: PortState,
    network_port: P,
    bmca: Bmca,
}

// START NEW INTERFACE

// Making this non-copy and non-clone ensures a single handle_send_timestamp
// per SendTimeCritical
pub struct TimestampContext;

pub enum PortAction<'a> {
    SendTimeCritical {
        context: TimestampContext,
        data: &'a [u8],
    },
    SendGeneral {
        data: &'a [u8],
    },
    ResetAnnounceTimer {
        duration: core::time::Duration,
    },
    ResetSyncTimer {
        duration: core::time::Duration,
    },
    ResetAnnounceReceiptTimer {
        duration: core::time::Duration,
    },
}

pub struct PortInBMCA;

impl<P> Port<P> {
    // Send timestamp for last timecritical message became available
    #[allow(unused)]
    pub fn handle_send_timestamp(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
    ) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Handle the announce timer going of
    pub fn handle_announce_timer(&mut self) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Handle the sync timer going of
    pub fn handle_sync_timer(&mut self) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Handle the announce receipt timer going of
    pub fn handle_announce_receipt_timer(&mut self) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Handle a message over the timecritical channel
    #[allow(unused)]
    pub fn handle_timecritical_receive(
        &mut self,
        data: &[u8],
        timestamp: Time,
    ) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Handle a general ptp message
    #[allow(unused)]
    pub fn handle_general_receive(
        &mut self,
        data: &[u8],
    ) -> impl Iterator<Item = PortAction<'_>> + '_ {
        todo!();
        #[allow(unreachable_code)]
        core::iter::empty()
    }

    // Start a BMCA cycle and ensure this happens instantly from the perspective of
    // the port
    pub fn start_bmca(self) -> PortInBMCA {
        todo!()
    }
}

// Placeholder for type parameters that should be gone by the end of the
// refactor
#[allow(clippy::upper_case_acronyms)]
pub struct REMOVE;

impl PortInBMCA {
    // End a BMCA cycle and make the port available again
    pub fn end_bmca(self) -> (Port<REMOVE>, impl Iterator<Item = PortAction<'static>>) {
        #[allow(unreachable_code)]
        (todo!(), core::iter::empty())
    }
}
// END NEW INTERFACE

impl<P> Port<P> {
    /// Create a new port from a port dataset on a given interface.
    ///
    /// For example, when using the `statime-linux` network runtime, a port on
    /// `eth0` for an ordinary clock can be created with
    ///
    /// ```ignore
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
    /// let port = Port::new(port_ds, &mut network_runtime, "eth0".parse().unwrap());
    /// ```
    pub async fn new<NR>(
        config: PortConfig,
        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
    ) -> Self
    where
        NR: NetworkRuntime<NetworkPort = P>,
    {
        let network_port = runtime
            .open(interface)
            .await
            .expect("Could not create network port");

        let bmca = Bmca::new(
            Duration::from_log_interval(config.log_announce_interval).into(),
            config.port_identity,
        );

        Port {
            config,
            port_state: PortState::Listening,
            network_port,
            bmca,
        }
    }

    fn set_forced_port_state(&mut self, state: PortState) {
        log::info!(
            "new state for port {}: {} -> {}",
            self.config.port_identity.port_number,
            self.port_state,
            state
        );
        self.port_state = state;
    }

    fn set_recommended_port_state<F: Future>(
        &mut self,
        recommended_state: &RecommendedState,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
    ) {
        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => {
                let remote_master = announce_message.header().source_port_identity();
                let state = PortState::Slave(SlaveState::new(remote_master));

                match &self.port_state {
                    PortState::Listening | PortState::Master(_) | PortState::Passive => {
                        self.set_forced_port_state(state);
                        announce_receipt_timeout.reset();
                    }
                    PortState::Slave(old_state) => {
                        if old_state.remote_master() != remote_master {
                            self.set_forced_port_state(state);
                            announce_receipt_timeout.reset();
                        }
                    }
                }
            }
            RecommendedState::M1(_) | RecommendedState::M2(_) | RecommendedState::M3(_) => {
                match self.port_state {
                    PortState::Listening | PortState::Slave(_) | PortState::Passive => {
                        self.set_forced_port_state(PortState::Master(MasterState::new()))
                    }
                    PortState::Master(_) => (),
                }
            }
            RecommendedState::P1(_) | RecommendedState::P2(_) => match self.port_state {
                PortState::Listening | PortState::Slave(_) | PortState::Master(_) => {
                    self.set_forced_port_state(PortState::Passive)
                }
                PortState::Passive => (),
            },
        }
    }

    pub(crate) fn identity(&self) -> PortIdentity {
        self.config.port_identity
    }
}

impl<P: NetworkPort> Port<P> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_port<F: Future>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        filter: &RefCell<impl Filter>,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        sync_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        announce_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        default_ds: &DefaultDS,
        time_properties_ds: &TimePropertiesDS,
        parent_ds: &ParentDS,
        current_ds: &CurrentDS,
        mut stop: Signal<'_>,
    ) {
        loop {
            log::trace!("Loop iter port {}", self.config.port_identity.port_number);
            let timeouts = select::select3(
                announce_receipt_timeout.next(),
                sync_timeout.next(),
                announce_timeout.next(),
            );
            let packet = self.network_port.recv();
            match select::select3(timeouts, packet, stop.wait_for()).await {
                Either3::First(timeout) => match timeout {
                    Either3::First(_) => {
                        log::trace!(
                            "Port {} force master timeout",
                            self.config.port_identity.port_number
                        );
                        // No announces received for a long time, become master
                        match self.port_state {
                            PortState::Master(_) => (),
                            _ => self.set_forced_port_state(PortState::Master(MasterState::new())),
                        }
                    }
                    Either3::Second(_) => {
                        log::trace!(
                            "Port {} sync timeout",
                            self.config.port_identity.port_number
                        );
                        // Send sync message
                        if let Err(error) = self.send_sync(local_clock, default_ds).await {
                            log::error!("{:?}", error);
                        }
                    }
                    Either3::Third(_) => {
                        log::trace!(
                            "Port {} announce timeout",
                            self.config.port_identity.port_number
                        );
                        // Send announce message
                        if let Err(error) = self
                            .send_announce(
                                local_clock,
                                default_ds,
                                time_properties_ds,
                                parent_ds,
                                current_ds,
                            )
                            .await
                        {
                            log::error!("{:?}", error);
                        }
                    }
                },
                Either3::Second(Ok(packet)) => {
                    log::trace!(
                        "Port {} message received: {:?}",
                        self.config.port_identity.port_number,
                        packet
                    );
                    // Process packet
                    if let Err(error) = self
                        .handle_packet(
                            packet,
                            local_clock,
                            filter,
                            announce_receipt_timeout,
                            default_ds,
                            time_properties_ds,
                        )
                        .await
                    {
                        log::error!("{:?}", error);
                    }
                }
                Either3::Second(Err(error)) => log::error!("failed to parse packet {:?}", error),
                Either3::Third(_) => {
                    log::trace!(
                        "Port {} bmca trigger",
                        self.config.port_identity.port_number
                    );
                    break;
                }
            }
        }
    }

    pub(crate) fn best_local_announce_message(
        &mut self,
        current_time: WireTimestamp,
    ) -> Option<BestAnnounceMessage> {
        self.bmca.take_best_port_announce_message(current_time)
    }

    pub(crate) fn set_recommended_state<F: Future>(
        &mut self,
        recommended_state: RecommendedState,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        time_properties_ds: &mut TimePropertiesDS,
        current_ds: &mut CurrentDS,
        parent_ds: &mut ParentDS,
    ) -> Result<()> {
        self.set_recommended_port_state(&recommended_state, announce_receipt_timeout);

        match recommended_state {
            RecommendedState::M1(defaultds) | RecommendedState::M2(defaultds) => {
                current_ds.steps_removed = 0;
                current_ds.offset_from_master = Duration::ZERO;
                current_ds.mean_delay = Duration::ZERO;

                parent_ds.parent_port_identity.clock_identity = defaultds.clock_identity;
                parent_ds.parent_port_identity.port_number = 0;
                parent_ds.grandmaster_identity = defaultds.clock_identity;
                parent_ds.grandmaster_clock_quality = defaultds.clock_quality;
                parent_ds.grandmaster_priority_1 = defaultds.priority_1;
                parent_ds.grandmaster_priority_2 = defaultds.priority_2;

                time_properties_ds.leap59 = false;
                time_properties_ds.leap61 = false;
                time_properties_ds.current_utc_offset = 37;
                time_properties_ds.current_utc_offset_valid = false;
                time_properties_ds.ptp_timescale = true;
                time_properties_ds.time_traceable = false;
                time_properties_ds.frequency_traceable = false;
                time_properties_ds.time_source = TimeSource::InternalOscillator;
            }
            RecommendedState::M3(_) | RecommendedState::P1(_) | RecommendedState::P2(_) => {}
            RecommendedState::S1(announce_message) => {
                current_ds.steps_removed = announce_message.steps_removed() + 1;

                parent_ds.parent_port_identity = announce_message.header().source_port_identity();
                parent_ds.grandmaster_identity = announce_message.grandmaster_identity();
                parent_ds.grandmaster_clock_quality = announce_message.grandmaster_clock_quality();
                parent_ds.grandmaster_priority_1 = announce_message.grandmaster_priority_1();
                parent_ds.grandmaster_priority_2 = announce_message.grandmaster_priority_2();

                *time_properties_ds = announce_message.time_properties();
            }
        }

        // TODO: Discuss if we should change the clock's own time properties, or keep
        // the master's time properties separately
        if let RecommendedState::S1(announce_message) = &recommended_state {
            // Update time properties
            *time_properties_ds = announce_message.time_properties();
        }

        Ok(())
    }

    async fn send_sync(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        self.port_state
            .send_sync(
                local_clock,
                &mut self.network_port,
                self.config.port_identity,
                default_ds,
            )
            .await
    }

    async fn send_announce(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        default_ds: &DefaultDS,
        time_properties: &TimePropertiesDS,
        parent_ds: &ParentDS,
        current_ds: &CurrentDS,
    ) -> Result<()> {
        self.port_state
            .send_announce(
                local_clock,
                default_ds,
                time_properties,
                parent_ds,
                current_ds,
                &mut self.network_port,
                self.config.port_identity,
            )
            .await
    }

    async fn handle_packet<F: Future>(
        &mut self,
        packet: NetworkPacket,
        local_clock: &RefCell<impl Clock>,
        filter: &RefCell<impl Filter>,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        default_ds: &DefaultDS,
        time_properties_ds: &TimePropertiesDS,
    ) -> Result<()> {
        let message = Message::deserialize(&packet.data)?;

        // Only process messages from the same domain
        if message.header().sdo_id() != default_ds.sdo_id
            || message.header().domain_number() != default_ds.domain_number
        {
            return Ok(());
        }

        if let Message::Announce(announce) = &message {
            log::debug!(
                "Received announce message on port {}, {:?}.",
                self.config.port_identity.port_number,
                message
            );
            self.bmca
                .register_announce_message(announce, packet.timestamp.into());
            announce_receipt_timeout.reset();
        } else {
            self.port_state
                .handle_message(
                    message,
                    packet.timestamp,
                    &mut self.network_port,
                    self.config.min_delay_req_interval(),
                    self.config.port_identity,
                    default_ds,
                )
                .await?;

            // If the received message allowed the (slave) state to calculate its offset
            // from the master, update the local clock
            if let Some(measurement) = self.port_state.extract_measurement() {
                let (offset, freq_corr) = filter
                    .try_borrow_mut()
                    .map(|mut borrow| borrow.absorb(measurement))
                    .map_err(|_| PortError::FilterBusy)?;

                let mut local_clock = local_clock
                    .try_borrow_mut()
                    .map_err(|_| PortError::ClockBusy)?;

                if let Err(error) = local_clock.adjust(offset, freq_corr, time_properties_ds) {
                    log::error!("failed to adjust clock: {:?}", error);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn announce_interval(&self) -> Duration {
        Duration::from_log_interval(self.config.log_announce_interval)
    }

    pub(crate) fn sync_interval(&self) -> Duration {
        Duration::from_log_interval(self.config.log_sync_interval)
    }

    pub(crate) fn announce_receipt_interval(&self) -> Duration {
        Duration::from_log_interval(self.config.log_announce_interval)
            * self.config.announce_receipt_timeout
    }

    pub(crate) fn state(&self) -> &PortState {
        &self.port_state
    }
}
