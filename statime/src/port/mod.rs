use core::ops::Deref;

use arrayvec::ArrayVec;
use atomic_refcell::{AtomicRef, AtomicRefCell};
pub use measurement::Measurement;
use rand::Rng;
use state::{MasterState, PortState};

use self::state::SlaveState;
use crate::{
    bmc::{
        acceptable_master::AcceptableMasterList,
        bmca::{BestAnnounceMessage, Bmca, RecommendedState},
    },
    clock::Clock,
    config::PortConfig,
    datastructures::{
        common::{LeapIndicator, PortIdentity, TimeSource},
        datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
        messages::{Message, MessageBody},
    },
    filters::{Filter, FilterUpdate},
    ptp_instance::PtpInstanceState,
    time::Duration,
    Time, MAX_DATA_LEN,
};

// Needs to be here because of use rules
macro_rules! actions {
    [] => {
        {
            crate::port::PortActionIterator::from(::arrayvec::ArrayVec::new())
        }
    };
    [$action:expr] => {
        {
            let mut list = ::arrayvec::ArrayVec::new();
            list.push($action);
            PortActionIterator::from(list)
        }
    };
    [$action1:expr, $action2:expr] => {
        {
            let mut list = ::arrayvec::ArrayVec::new();
            list.push($action1);
            list.push($action2);
            PortActionIterator::from(list)
        }
    };
}

mod measurement;
mod sequence_id;
pub(crate) mod state;

/// A single port of the PTP instance
///
/// One of these needs to be created per port of the PTP instance.
#[derive(Debug)]
pub struct Port<L, A, R, C, F: Filter> {
    config: PortConfig<()>,
    filter_config: F::Config,
    clock: C,
    // PortDS port_identity
    pub(crate) port_identity: PortIdentity,
    // Corresponds with PortDS port_state and enabled
    port_state: PortState<F>,
    bmca: Bmca<A>,
    packet_buffer: [u8; MAX_DATA_LEN],
    lifecycle: L,
    rng: R,
}

#[derive(Debug)]
pub struct Running<'a> {
    state_refcell: &'a AtomicRefCell<PtpInstanceState>,
    state: AtomicRef<'a, PtpInstanceState>,
}

#[derive(Debug)]
pub struct InBmca<'a> {
    pending_action: PortActionIterator<'static>,
    local_best: Option<BestAnnounceMessage>,
    state_refcell: &'a AtomicRefCell<PtpInstanceState>,
}

// Making this non-copy and non-clone ensures a single handle_send_timestamp
// per SendTimeCritical
#[derive(Debug)]
pub struct TimestampContext {
    inner: TimestampContextInner,
}

#[derive(Debug)]
enum TimestampContextInner {
    Sync { id: u16 },
    DelayReq { id: u16 },
}

#[derive(Debug)]
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
    ResetDelayRequestTimer {
        duration: core::time::Duration,
    },
    ResetAnnounceReceiptTimer {
        duration: core::time::Duration,
    },
    ResetFilterUpdateTimer {
        duration: core::time::Duration,
    },
}

const MAX_ACTIONS: usize = 2;

/// Guarantees to end user: Any set of actions will only ever contain a single
/// time critical send
#[derive(Debug)]
#[must_use]
pub struct PortActionIterator<'a> {
    internal: <ArrayVec<PortAction<'a>, MAX_ACTIONS> as IntoIterator>::IntoIter,
}

impl<'a> PortActionIterator<'a> {
    pub fn empty() -> Self {
        Self {
            internal: ArrayVec::new().into_iter(),
        }
    }
    fn from(list: ArrayVec<PortAction<'a>, MAX_ACTIONS>) -> Self {
        Self {
            internal: list.into_iter(),
        }
    }
    fn from_filter(update: FilterUpdate) -> Self {
        if let Some(duration) = update.next_update {
            actions![PortAction::ResetFilterUpdateTimer { duration }]
        } else {
            actions![]
        }
    }
}

impl<'a> Iterator for PortActionIterator<'a> {
    type Item = PortAction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.internal.next()
    }
}

impl<'a, A, C: Clock, F: Filter, R: Rng> Port<Running<'a>, A, R, C, F> {
    // Send timestamp for last timecritical message became available
    pub fn handle_send_timestamp(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
    ) -> PortActionIterator<'_> {
        let actions = self.port_state.handle_timestamp(
            context,
            timestamp,
            self.port_identity,
            &self.lifecycle.state.default_ds,
            &mut self.clock,
            &mut self.packet_buffer,
        );

        actions
    }

    // Handle the announce timer going of
    pub fn handle_announce_timer(&mut self) -> PortActionIterator<'_> {
        self.port_state.send_announce(
            self.lifecycle.state.deref(),
            &self.config,
            self.port_identity,
            &mut self.packet_buffer,
        )
    }

    // Handle the sync timer going of
    pub fn handle_sync_timer(&mut self) -> PortActionIterator<'_> {
        self.port_state.send_sync(
            &self.config,
            self.port_identity,
            &self.lifecycle.state.default_ds,
            &mut self.packet_buffer,
        )
    }

    // Handle the sync timer going of
    pub fn handle_delay_request_timer(&mut self) -> PortActionIterator<'_> {
        self.port_state.send_delay_request(
            &mut self.rng,
            &self.config,
            self.port_identity,
            &self.lifecycle.state.default_ds,
            &mut self.packet_buffer,
        )
    }

    // Handle the announce receipt timer going off
    pub fn handle_announce_receipt_timer(&mut self) -> PortActionIterator<'_> {
        // we didn't hear announce messages from other masters, so become master
        // ourselves
        match self.port_state {
            PortState::Master(_) => (),
            _ => self.set_forced_port_state(PortState::Master(MasterState::new())),
        }

        // Immediately start sending syncs and announces
        actions![
            PortAction::ResetAnnounceTimer {
                duration: core::time::Duration::from_secs(0)
            },
            PortAction::ResetSyncTimer {
                duration: core::time::Duration::from_secs(0)
            }
        ]
    }

    pub fn handle_filter_update_timer(&mut self) -> PortActionIterator {
        self.port_state.handle_filter_update(&mut self.clock)
    }

    // Start a BMCA cycle and ensure this happens instantly from the perspective of
    // the port
    pub fn start_bmca(self) -> Port<InBmca<'a>, A, R, C, F> {
        Port {
            port_state: self.port_state,
            config: self.config,
            filter_config: self.filter_config,
            clock: self.clock,
            port_identity: self.port_identity,
            bmca: self.bmca,
            rng: self.rng,
            packet_buffer: [0; MAX_DATA_LEN],
            lifecycle: InBmca {
                pending_action: actions![],
                local_best: None,
                state_refcell: self.lifecycle.state_refcell,
            },
        }
    }
}

impl<'a, A: AcceptableMasterList, C: Clock, F: Filter, R: Rng> Port<Running<'a>, A, R, C, F> {
    // Handle a message over the timecritical channel
    pub fn handle_timecritical_receive(
        &mut self,
        data: &[u8],
        timestamp: Time,
    ) -> PortActionIterator {
        let message = match Message::deserialize(data) {
            Ok(message) => message,
            Err(error) => {
                log::warn!("Could not parse packet: {:?}", error);
                return actions![];
            }
        };

        // Only process messages from the same domain
        if message.header().sdo_id != self.lifecycle.state.default_ds.sdo_id
            || message.header().domain_number != self.lifecycle.state.default_ds.domain_number
        {
            return actions![];
        }

        if message.is_event() {
            self.port_state.handle_event_receive(
                message,
                timestamp,
                self.config.min_delay_req_interval(),
                self.port_identity,
                &mut self.clock,
                &mut self.packet_buffer,
            )
        } else {
            self.handle_general_internal(message)
        }
    }

    // Handle a general ptp message
    pub fn handle_general_receive(&mut self, data: &[u8]) -> PortActionIterator {
        let message = match Message::deserialize(data) {
            Ok(message) => message,
            Err(error) => {
                log::warn!("Could not parse packet: {:?}", error);
                return actions![];
            }
        };

        // Only process messages from the same domain
        if message.header().sdo_id != self.lifecycle.state.default_ds.sdo_id
            || message.header().domain_number != self.lifecycle.state.default_ds.domain_number
        {
            return actions![];
        }

        self.handle_general_internal(message)
    }

    fn handle_general_internal(&mut self, message: Message<'_>) -> PortActionIterator<'_> {
        match message.body {
            MessageBody::Announce(announce) => {
                self.bmca
                    .register_announce_message(&message.header, &announce);
                actions![PortAction::ResetAnnounceReceiptTimer {
                    duration: self.config.announce_duration(&mut self.rng),
                }]
            }
            _ => {
                self.port_state
                    .handle_general_receive(message, self.port_identity, &mut self.clock)
            }
        }
    }
}

impl<'a, A, C, F: Filter, R> Port<InBmca<'a>, A, R, C, F> {
    // End a BMCA cycle and make the port available again
    pub fn end_bmca(self) -> (Port<Running<'a>, A, R, C, F>, PortActionIterator<'static>) {
        (
            Port {
                port_state: self.port_state,
                config: self.config,
                filter_config: self.filter_config,
                clock: self.clock,
                port_identity: self.port_identity,
                bmca: self.bmca,
                rng: self.rng,
                packet_buffer: [0; MAX_DATA_LEN],
                lifecycle: Running {
                    state_refcell: self.lifecycle.state_refcell,
                    state: self.lifecycle.state_refcell.borrow(),
                },
            },
            self.lifecycle.pending_action,
        )
    }
}

impl<L, A, R, C: Clock, F: Filter> Port<L, A, R, C, F> {
    fn set_forced_port_state(&mut self, mut state: PortState<F>) {
        log::info!(
            "new state for port {}: {} -> {}",
            self.port_identity.port_number,
            self.port_state,
            state
        );
        core::mem::swap(&mut self.port_state, &mut state);
        state.demobilize_filter(&mut self.clock);
    }
}

impl<L, A, R, C, F: Filter> Port<L, A, R, C, F> {
    pub fn is_steering(&self) -> bool {
        matches!(self.port_state, PortState::Slave(_))
    }

    pub(crate) fn state(&self) -> &PortState<F> {
        &self.port_state
    }

    pub(crate) fn number(&self) -> u16 {
        self.port_identity.port_number
    }
}

impl<'a, A: AcceptableMasterList, C: Clock, F: Filter, R: Rng> Port<InBmca<'a>, A, R, C, F> {
    pub(crate) fn calculate_best_local_announce_message(&mut self) {
        self.lifecycle.local_best = self.bmca.take_best_port_announce_message()
    }
}

impl<'a, A, C: Clock, F: Filter, R: Rng> Port<InBmca<'a>, A, R, C, F> {
    pub(crate) fn step_announce_age(&mut self, step: Duration) {
        self.bmca.step_age(step);
    }

    pub(crate) fn best_local_announce_message(&self) -> Option<BestAnnounceMessage> {
        // Announce messages received on a masterOnly PTP Port shall not be considered
        // in the operation of the best master clock algorithm or in the update
        // of data sets.
        if self.config.master_only {
            None
        } else {
            self.lifecycle.local_best
        }
    }

    pub(crate) fn set_recommended_state(
        &mut self,
        recommended_state: RecommendedState,
        time_properties_ds: &mut TimePropertiesDS,
        current_ds: &mut CurrentDS,
        parent_ds: &mut ParentDS,
        default_ds: &DefaultDS,
    ) {
        self.set_recommended_port_state(&recommended_state, default_ds);

        match recommended_state {
            RecommendedState::M1(defaultds) | RecommendedState::M2(defaultds) => {
                // a slave-only PTP port should never end up in the master state
                debug_assert!(!default_ds.slave_only);

                current_ds.steps_removed = 0;
                current_ds.offset_from_master = Duration::ZERO;
                current_ds.mean_delay = Duration::ZERO;

                parent_ds.parent_port_identity.clock_identity = defaultds.clock_identity;
                parent_ds.parent_port_identity.port_number = 0;
                parent_ds.grandmaster_identity = defaultds.clock_identity;
                parent_ds.grandmaster_clock_quality = defaultds.clock_quality;
                parent_ds.grandmaster_priority_1 = defaultds.priority_1;
                parent_ds.grandmaster_priority_2 = defaultds.priority_2;

                time_properties_ds.leap_indicator = LeapIndicator::NoLeap;
                time_properties_ds.current_utc_offset = None;
                time_properties_ds.ptp_timescale = true;
                time_properties_ds.time_traceable = false;
                time_properties_ds.frequency_traceable = false;
                time_properties_ds.time_source = TimeSource::InternalOscillator;
            }
            RecommendedState::M3(_) | RecommendedState::P1(_) | RecommendedState::P2(_) => {}
            RecommendedState::S1(announce_message) => {
                // a master-only PTP port should never end up in the slave state
                debug_assert!(!self.config.master_only);

                current_ds.steps_removed = announce_message.steps_removed + 1;

                parent_ds.parent_port_identity = announce_message.header.source_port_identity;
                parent_ds.grandmaster_identity = announce_message.grandmaster_identity;
                parent_ds.grandmaster_clock_quality = announce_message.grandmaster_clock_quality;
                parent_ds.grandmaster_priority_1 = announce_message.grandmaster_priority_1;
                parent_ds.grandmaster_priority_2 = announce_message.grandmaster_priority_2;

                *time_properties_ds = announce_message.time_properties();

                if let Err(error) = self.clock.set_properties(time_properties_ds) {
                    log::error!("Could not update clock: {:?}", error);
                }
            }
        }

        // TODO: Discuss if we should change the clock's own time properties, or keep
        // the master's time properties separately
        if let RecommendedState::S1(announce_message) = &recommended_state {
            // Update time properties
            *time_properties_ds = announce_message.time_properties();
        }
    }

    fn set_recommended_port_state(
        &mut self,
        recommended_state: &RecommendedState,
        default_ds: &DefaultDS,
    ) {
        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => {
                // a master-only PTP port should never end up in the slave state
                debug_assert!(!self.config.master_only);

                let remote_master = announce_message.header.source_port_identity;

                let update_state = match &self.port_state {
                    PortState::Listening | PortState::Master(_) | PortState::Passive => true,
                    PortState::Slave(old_state) => old_state.remote_master() != remote_master,
                };

                if update_state {
                    let state = PortState::Slave(SlaveState::new(
                        remote_master,
                        self.filter_config.clone(),
                    ));
                    self.set_forced_port_state(state);

                    let duration = self.config.announce_duration(&mut self.rng);
                    let reset_announce = PortAction::ResetAnnounceReceiptTimer { duration };
                    let reset_delay = PortAction::ResetDelayRequestTimer {
                        duration: core::time::Duration::ZERO,
                    };
                    self.lifecycle.pending_action = actions![reset_announce, reset_delay];
                }
            }
            RecommendedState::M1(_) | RecommendedState::M2(_) | RecommendedState::M3(_) => {
                if default_ds.slave_only {
                    match self.port_state {
                        PortState::Listening => { /* do nothing */ }
                        PortState::Slave(_) | PortState::Passive => {
                            self.set_forced_port_state(PortState::Listening);

                            // consistent with Port<InBmca>::new()
                            let duration = self.config.announce_duration(&mut self.rng);
                            let reset_announce = PortAction::ResetAnnounceReceiptTimer { duration };
                            self.lifecycle.pending_action = actions![reset_announce];
                        }
                        PortState::Master(_) => {
                            let msg = "slave-only PTP port should not be in master state";
                            debug_assert!(!default_ds.slave_only, "{msg}");
                            log::error!("{msg}");
                        }
                    }
                } else {
                    match self.port_state {
                        PortState::Listening | PortState::Slave(_) | PortState::Passive => {
                            self.set_forced_port_state(PortState::Master(MasterState::new()));

                            // Immediately start sending announces and syncs
                            let duration = core::time::Duration::from_secs(0);
                            self.lifecycle.pending_action = actions![
                                PortAction::ResetAnnounceTimer { duration },
                                PortAction::ResetSyncTimer { duration }
                            ];
                        }
                        PortState::Master(_) => { /* do nothing */ }
                    }
                }
            }
            RecommendedState::P1(_) | RecommendedState::P2(_) => match self.port_state {
                PortState::Listening | PortState::Slave(_) | PortState::Master(_) => {
                    self.set_forced_port_state(PortState::Passive)
                }
                PortState::Passive => {}
            },
        }
    }
}

impl<'a, A, C, F: Filter, R: Rng> Port<InBmca<'a>, A, R, C, F> {
    /// Create a new port from a port dataset on a given interface.
    pub(crate) fn new(
        state_refcell: &'a AtomicRefCell<PtpInstanceState>,
        config: PortConfig<A>,
        filter_config: F::Config,
        clock: C,
        port_identity: PortIdentity,
        mut rng: R,
    ) -> Self {
        let duration = config.announce_duration(&mut rng);
        let bmca = Bmca::new(
            config.acceptable_master_list,
            config.announce_interval.as_duration().into(),
            port_identity,
        );

        Port {
            config: PortConfig {
                acceptable_master_list: (),
                delay_mechanism: config.delay_mechanism,
                announce_interval: config.announce_interval,
                announce_receipt_timeout: config.announce_receipt_timeout,
                sync_interval: config.sync_interval,
                master_only: config.master_only,
                delay_asymmetry: config.delay_asymmetry,
            },
            filter_config,
            clock,
            port_identity,
            port_state: PortState::Listening,
            bmca,
            rng,
            packet_buffer: [0; MAX_DATA_LEN],
            lifecycle: InBmca {
                pending_action: actions![PortAction::ResetAnnounceReceiptTimer { duration }],
                local_best: None,
                state_refcell,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastructures::messages::{AnnounceMessage, Header, PtpVersion},
        BasicFilter, DelayMechanism, InstanceConfig, Interval,
    };

    struct TestClock;

    impl Clock for TestClock {
        type Error = ();

        fn set_frequency(&mut self, _freq: f64) -> Result<Time, Self::Error> {
            Ok(Time::default())
        }

        fn now(&self) -> Time {
            panic!("Shouldn't be called");
        }

        fn set_properties(
            &mut self,
            _time_properties_ds: &crate::TimePropertiesDS,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn step_clock(&mut self, _offset: Duration) -> Result<Time, Self::Error> {
            Ok(Time::default())
        }
    }

    fn default_announce_message_header() -> Header {
        Header {
            sdo_id: Default::default(),
            version: PtpVersion::new(2, 1).unwrap(),
            domain_number: Default::default(),
            alternate_master_flag: false,
            two_step_flag: false,
            unicast_flag: false,
            ptp_profile_specific_1: false,
            ptp_profile_specific_2: false,
            leap61: false,
            leap59: false,
            current_utc_offset_valid: false,
            ptp_timescale: false,
            time_tracable: false,
            frequency_tracable: false,
            synchronization_uncertain: false,
            correction_field: Default::default(),
            source_port_identity: Default::default(),
            sequence_id: Default::default(),
            log_message_interval: Default::default(),
        }
    }

    fn default_announce_message() -> AnnounceMessage {
        AnnounceMessage {
            header: default_announce_message_header(),
            origin_timestamp: Default::default(),
            current_utc_offset: Default::default(),
            grandmaster_priority_1: Default::default(),
            grandmaster_clock_quality: Default::default(),
            grandmaster_priority_2: Default::default(),
            grandmaster_identity: Default::default(),
            steps_removed: Default::default(),
            time_source: Default::default(),
        }
    }

    #[test]
    fn test_announce_receive() {
        let default_ds = DefaultDS::new(InstanceConfig {
            clock_identity: Default::default(),
            priority_1: 255,
            priority_2: 255,
            domain_number: 0,
            slave_only: false,
            sdo_id: Default::default(),
        });

        let parent_ds = ParentDS::new(default_ds);

        let state = AtomicRefCell::new(PtpInstanceState {
            default_ds,
            current_ds: Default::default(),
            parent_ds,
            time_properties_ds: Default::default(),
        });

        let port = Port::<_, _, _, _, BasicFilter>::new(
            &state,
            PortConfig {
                acceptable_master_list: (),
                delay_mechanism: DelayMechanism::E2E {
                    interval: Interval::from_log_2(1),
                },
                announce_interval: Interval::from_log_2(1),
                announce_receipt_timeout: 3,
                sync_interval: Interval::from_log_2(0),
                master_only: false,
                delay_asymmetry: Duration::ZERO,
            },
            0.25,
            TestClock,
            Default::default(),
            rand::rngs::mock::StepRng::new(2, 1),
        );

        let (mut port, _) = port.end_bmca();

        let mut announce = default_announce_message();
        announce.header.source_port_identity.clock_identity.0 = [1, 2, 3, 4, 5, 6, 7, 8];
        let announce_message = Message {
            header: announce.header,
            body: MessageBody::Announce(announce),
            suffix: Default::default(),
        };
        let mut packet = [0; MAX_DATA_LEN];
        let packet_len = announce_message.serialize(&mut packet).unwrap();
        let packet = &packet[..packet_len];

        let mut actions = port.handle_general_receive(packet);
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut actions = port.handle_general_receive(packet);
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut actions = port.handle_general_receive(packet);
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut port = port.start_bmca();
        port.calculate_best_local_announce_message();
        assert!(port.best_local_announce_message().is_some());
    }

    #[test]
    fn test_announce_receive_via_timecritical() {
        let default_ds = DefaultDS::new(InstanceConfig {
            clock_identity: Default::default(),
            priority_1: 255,
            priority_2: 255,
            domain_number: 0,
            slave_only: false,
            sdo_id: Default::default(),
        });

        let parent_ds = ParentDS::new(default_ds);

        let state = AtomicRefCell::new(PtpInstanceState {
            default_ds,
            current_ds: Default::default(),
            parent_ds,
            time_properties_ds: Default::default(),
        });

        let port = Port::<_, _, _, _, BasicFilter>::new(
            &state,
            PortConfig {
                acceptable_master_list: (),
                delay_mechanism: DelayMechanism::E2E {
                    interval: Interval::from_log_2(1),
                },
                announce_interval: Interval::from_log_2(1),
                announce_receipt_timeout: 3,
                sync_interval: Interval::from_log_2(0),
                master_only: false,
                delay_asymmetry: Duration::ZERO,
            },
            0.25,
            TestClock,
            Default::default(),
            rand::rngs::mock::StepRng::new(2, 1),
        );

        let (mut port, _) = port.end_bmca();

        let mut announce = default_announce_message();
        announce.header.source_port_identity.clock_identity.0 = [1, 2, 3, 4, 5, 6, 7, 8];
        let announce_message = Message {
            header: announce.header,
            body: MessageBody::Announce(announce),
            suffix: Default::default(),
        };
        let mut packet = [0; MAX_DATA_LEN];
        let packet_len = announce_message.serialize(&mut packet).unwrap();
        let packet = &packet[..packet_len];

        let mut actions = port.handle_timecritical_receive(packet, Time::from_micros(1));
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut actions = port.handle_timecritical_receive(packet, Time::from_micros(2));
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut actions = port.handle_timecritical_receive(packet, Time::from_micros(3));
        let Some(PortAction::ResetAnnounceReceiptTimer { .. }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let mut port = port.start_bmca();
        port.calculate_best_local_announce_message();
        assert!(port.best_local_announce_message().is_some());
    }
}
