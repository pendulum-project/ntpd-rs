use sequence_id::SequenceIdGenerator;

use crate::bmc::bmca::{Bmca, RecommendedState};
use crate::clock::Watch;
use crate::datastructures::common::{PortIdentity, TimeSource, Timestamp};
use crate::datastructures::datasets::{DefaultDS, PortDS, TimePropertiesDS};
use crate::datastructures::messages::{
    AnnounceMessage, DelayRespMessage, FollowUpMessage, Message, MessageBuilder,
};
use crate::network::{NetworkPacket, NetworkPort, NetworkRuntime};
use crate::time::{Duration, Instant};

mod sequence_id;

pub struct Port<P, W> {
    pub(crate) bmca_watch: W,
    announce_timeout_watch: W,
    announce_watch: W,
    sync_watch: W,
    state: State,
    tc_port: P,
    nc_port: P,
    delay_req_ids: SequenceIdGenerator,
    port_ds: PortDS,
    bmca: Bmca,
    announce_seq_id: u16,
    sync_seq_id: u16,
    follow_up_seq_id: u16,
    delay_resp_seq_id: u16,
}

impl<P: NetworkPort, W: Watch> Port<P, W> {
    pub fn new<NR>(
        port_ds: PortDS,
        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
        bmca_watch: W,
        announce_timeout_watch: W,
        announce_watch: W,
        sync_watch: W,
    ) -> Self
    where
        NR: NetworkRuntime<PortType = P>,
    {
        // Ptp needs two ports, 1 time critical one and 1 general port
        let tc_port = runtime
            .open(interface.clone(), true)
            .expect("Could not create time critical port");
        let nc_port = runtime
            .open(interface, false)
            .expect("Could not create non time critical port");

        let bmca = Bmca::new(
            Duration::from_log_interval(port_ds.log_announce_interval).into(),
            port_ds.port_identity,
        );

        Port {
            bmca_watch,
            announce_timeout_watch,
            announce_watch,
            sync_watch,
            state: State::Listening,
            tc_port,
            nc_port,
            delay_req_ids: SequenceIdGenerator::default(),
            port_ds,
            bmca,
            announce_seq_id: 0,
            sync_seq_id: 0,
            follow_up_seq_id: 0,
            delay_resp_seq_id: 0,
        }
    }

    pub fn handle_alarm(&mut self, id: W::WatchId, current_time: Instant, default_ds: &DefaultDS) {
        // When the announce timout expires, it means there
        // have been no announce messages in a while, so we
        // force a switch to the master state
        if id == self.announce_timeout_watch.id() {
            log::info!("Announce interval timeout");

            self.state = State::Master;

            // Reset sequences in portdata
            self.announce_seq_id = 0;
            self.sync_seq_id = 0;
            self.follow_up_seq_id = 0;
            self.delay_resp_seq_id = 0;

            log::info!("New state for port: Master");

            // Start sending announce messages
            self.announce_watch.set_alarm(Duration::from_log_interval(
                self.port_ds.log_announce_interval,
            ));

            // Start sending sync messages
            self.sync_watch
                .set_alarm(Duration::from_log_interval(self.port_ds.log_sync_interval));
        }

        // When the announce watch expires, send an announce message and restart
        if id == self.announce_watch.id() {
            self.send_announce_message(default_ds);
            self.announce_watch.set_alarm(Duration::from_log_interval(
                self.port_ds.log_announce_interval,
            ));
        }

        // When the sync watch expires, send a sync message and restart
        if id == self.sync_watch.id() {
            self.send_sync_message(current_time);

            // TODO: Is the follow up a config?
            self.send_follow_up_message(current_time);

            self.sync_watch
                .set_alarm(Duration::from_log_interval(self.port_ds.log_sync_interval));
        }
    }

    /// Send an announce message
    pub fn send_announce_message(&mut self, default_ds: &DefaultDS) {
        match self.state {
            State::Master => {
                let announce_message = MessageBuilder::new()
                    .sequence_id(self.announce_seq_id)
                    .source_port_identity(self.port_ds.port_identity)
                    .announce_message(
                        Timestamp::default(),             //origin_timestamp: Timestamp,
                        0,                                // TODO implement current_utc_offset: u16,
                        default_ds.priority_1,            //grandmaster_priority_1: u8,
                        default_ds.clock_quality,         //grandmaster_clock_quality: ClockQuality,
                        default_ds.priority_2,            //grandmaster_priority_2: u8,
                        default_ds.clock_identity,        //grandmaster_identity: ClockIdentity,
                        0,                                // TODO implement steps_removed: u16,
                        TimeSource::from_primitive(0xa0), // TODO implement time_source: TimeSource,
                    );

                self.announce_seq_id = self.announce_seq_id.wrapping_add(1);
                let announce_message_encode = announce_message.serialize_vec().unwrap();
                self.nc_port.send(&announce_message_encode);

                Some(())
            }
            _ => None,
        };
    }

    /// Send a sync message
    pub fn send_sync_message(&mut self, current_time: Instant) {
        match self.state {
            State::Master => {
                let sync_message = MessageBuilder::new()
                    .sequence_id(self.sync_seq_id)
                    .source_port_identity(self.port_ds.port_identity)
                    .sync_message(Timestamp::from(current_time));

                self.sync_seq_id = self.sync_seq_id.wrapping_add(1);
                let sync_message_encode = sync_message.serialize_vec().unwrap();
                self.tc_port.send(&sync_message_encode);

                Some(())
            }
            _ => None,
        };
    }

    /// Send a follow up message
    pub fn send_follow_up_message(&mut self, current_time: Instant) {
        match self.state {
            State::Master => {
                let follow_up_message = MessageBuilder::new()
                    .sequence_id(self.sync_seq_id)
                    .source_port_identity(self.port_ds.port_identity)
                    .follow_up_message(Timestamp::from(current_time));

                self.follow_up_seq_id = self.follow_up_seq_id.wrapping_add(1);
                let follow_up_message_encode = follow_up_message.serialize_vec().unwrap();
                self.nc_port.send(&follow_up_message_encode);

                Some(())
            }
            _ => None,
        };
    }

    pub fn handle_network(
        &mut self,
        packet: &NetworkPacket,
        current_time: Instant,
        default_ds: &DefaultDS,
    ) {
        self.process_message(packet, current_time, default_ds);
    }

    /// Process messages, but only if they are from the same domain
    fn process_message(
        &mut self,
        packet: &NetworkPacket,
        current_time: Instant,
        default_ds: &DefaultDS,
    ) -> Option<()> {
        let message = Message::deserialize(&packet.data).ok()?;
        if message.header().sdo_id() != default_ds.sdo_id
            || message.header().domain_number() != default_ds.domain_number
        {
            return None;
        }

        self.handle_message(message, packet.timestamp);

        #[allow(clippy::single_match)]
        match message {
            Message::Announce(announce) => {
                self.bmca
                    .register_announce_message(&announce, current_time.into());

                // When an announce message is received, restart announce receipt timeout timer
                self.announce_timeout_watch
                    .set_alarm(Duration::from_log_interval(
                        self.port_ds.announce_receipt_timeout as i8
                            * self.port_ds.log_announce_interval,
                    ));
            }
            _ => {}
        };

        None
    }

    pub fn extract_measurement(&mut self) -> Option<Measurement> {
        match &mut self.state {
            State::Slave(state) => state.extract_measurement(),
            _ => None,
        }
    }

    pub fn take_best_port_announce_message(
        &mut self,
        current_time: Instant,
    ) -> Option<(AnnounceMessage, Timestamp, PortIdentity)> {
        self.bmca
            .take_best_port_announce_message(current_time.into())
    }

    pub fn perform_state_decision(
        &mut self,
        best_global_announce_message: Option<(&AnnounceMessage, &PortIdentity)>,
        best_port_announce_message: Option<(&AnnounceMessage, &PortIdentity)>,
        default_ds: &DefaultDS,
        time_properties_ds: &mut TimePropertiesDS,
    ) {
        let own_data = DefaultDS::new_oc(
            self.port_ds.port_identity.clock_identity,
            default_ds.priority_1,
            default_ds.priority_2,
            0,
            true,
            1337,
        );

        let recommended_state = Bmca::calculate_recommended_state(
            &own_data,
            best_global_announce_message,
            best_port_announce_message,
            &self.state,
        );

        if let Some(recommended_state) = recommended_state {
            self.handle_recommended_state(&recommended_state);
            #[allow(clippy::single_match)]
            match &recommended_state {
                RecommendedState::S1(announce_message) => {
                    *time_properties_ds = announce_message.time_properties();
                }
                _ => {}
            }
        }
    }

    pub fn announce_interval(&self) -> Duration {
        Duration::from_log_interval(self.port_ds.log_announce_interval)
    }

    fn handle_message(&mut self, message: Message, timestamp: Option<Instant>) -> Option<()> {
        match &mut self.state {
            State::Slave(state) => {
                if message.header().source_port_identity() != state.remote_master {
                    return None;
                }

                match message {
                    Message::Sync(message) => {
                        let timestamp = timestamp?;

                        state.sync_id = Some(message.header().sequence_id());
                        state.sync_recv_time = Some(timestamp);
                        state.delay_send_time = None;
                        state.delay_recv_time = None;

                        if message.header().two_step_flag() {
                            state.sync_correction =
                                Some(Duration::from(message.header().correction_field()));
                            state.sync_send_time = None;
                        } else {
                            state.sync_correction = None;
                            state.sync_send_time = Some(
                                Instant::from(message.origin_timestamp())
                                    + Duration::from(message.header().correction_field()),
                            );
                        }

                        if state.mean_delay.is_none()
                            || state.next_delay_measurement.unwrap_or_default() < timestamp
                        {
                            let delay_id = self.delay_req_ids.generate();
                            let delay_req = MessageBuilder::new()
                                .source_port_identity(self.port_ds.port_identity)
                                .sequence_id(delay_id)
                                .log_message_interval(0x7F)
                                .delay_req_message(Timestamp::default());
                            let delay_req_encode = delay_req.serialize_vec().unwrap();
                            state.delay_send_id = Some(
                                self.tc_port
                                    .send(&delay_req_encode)
                                    .expect("Program error: missing timestamp id"),
                            );
                            state.delay_id = Some(delay_id);
                            state.mean_delay = None;
                        } else {
                            state.delay_id = None;
                        }

                        if let Some(follow_up) = state.pending_followup {
                            state.handle_followup(follow_up);
                        }

                        Some(())
                    }
                    Message::FollowUp(message) => state.handle_followup(message),
                    Message::DelayResp(message) => state.handle_delayresp(message),
                    _ => None,
                }
            }
            State::Master => {
                // Always ignore messages from own port
                if message.header().source_port_identity() == self.port_ds.port_identity {
                    return None;
                }

                match message {
                    Message::DelayReq(message) => {
                        let timestamp = timestamp?;
                        // Send delay response
                        let delay_resp_message = MessageBuilder::new()
                            .sequence_id(self.delay_resp_seq_id)
                            .source_port_identity(self.port_ds.port_identity)
                            .delay_resp_message(
                                Timestamp::from(timestamp),
                                message.header().source_port_identity(),
                            );

                        self.delay_resp_seq_id = self.delay_resp_seq_id.wrapping_add(1);
                        let delay_resp_encode = delay_resp_message.serialize_vec().unwrap();
                        self.nc_port.send(&delay_resp_encode);

                        Some(())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: Instant) -> Option<()> {
        match &mut self.state {
            State::Slave(state) => state.handle_send_timestamp(id, timestamp),
            _ => None,
        }
    }

    fn handle_recommended_state(&mut self, recommended_state: &RecommendedState) {
        let log_announce_interval = self.port_ds.log_announce_interval;
        let log_sync_interval = self.port_ds.log_sync_interval;

        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => match &mut self.state {
                State::Listening => {
                    self.state = State::Slave(StateSlave {
                        remote_master: announce_message.header().source_port_identity(),
                        ..Default::default()
                    });

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
                        ));

                    log::info!(
                        "New state for port: Listening -> Slave. Remote master: {:?}",
                        announce_message
                            .header()
                            .source_port_identity()
                            .clock_identity
                    );
                }

                State::Slave(slave_state) => {
                    slave_state.remote_master = announce_message.header().source_port_identity();
                }

                // Transition MASTER to SLAVE
                State::Master => {
                    self.state = State::Slave(StateSlave {
                        remote_master: announce_message.header().source_port_identity(),
                        ..Default::default()
                    });

                    // Stop MASTER watches
                    self.announce_watch.clear();
                    self.sync_watch.clear();

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
                        ));

                    log::info!("New state for port: Master -> Slave");
                }
            },

            // Recommended state is master
            RecommendedState::M2(default_ds) => match &mut self.state {
                // Stay master
                State::Master => (),

                // Otherwise become master
                _ => {
                    // Stop the announce timeout alarm
                    self.announce_timeout_watch.clear();

                    self.state = State::Master;

                    // Reset sequences in portdata?
                    self.announce_seq_id = 0;
                    self.sync_seq_id = 0;
                    self.follow_up_seq_id = 0;
                    self.delay_resp_seq_id = 0;

                    log::info!("New state for port: Master");

                    // Start sending announce messages
                    self.announce_watch
                        .set_alarm(Duration::from_log_interval(log_announce_interval));

                    // Start sending sync messages
                    self.sync_watch
                        .set_alarm(Duration::from_log_interval(log_sync_interval));
                }
            },

            // All other cases
            _ => match &mut self.state {
                State::Listening => {
                    // Ignore
                }

                _ => {
                    self.state = State::Listening;

                    // Stop MASTER watches
                    self.announce_watch.clear();
                    self.sync_watch.clear();

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
                        ));

                    log::info!("New state for port: Listening");
                }
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Measurement {
    pub event_time: Instant,
    pub master_offset: Duration,
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum State {
    Listening,
    Slave(StateSlave),
    Master,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct StateSlave {
    remote_master: PortIdentity,
    mean_delay: Option<Duration>,
    sync_id: Option<u16>,
    delay_id: Option<u16>,
    delay_send_id: Option<usize>,
    sync_correction: Option<Duration>,
    sync_send_time: Option<Instant>,
    sync_recv_time: Option<Instant>,
    delay_send_time: Option<Instant>,
    delay_recv_time: Option<Instant>,
    next_delay_measurement: Option<Instant>,
    pending_followup: Option<FollowUpMessage>,
}

impl StateSlave {
    fn handle_followup(&mut self, message: FollowUpMessage) -> Option<()> {
        // Ignore messages not belonging to currently processing sync
        if self.sync_id != Some(message.header().sequence_id()) {
            self.pending_followup = Some(message); // Store it for a potentially coming sync
            return None;
        }

        // Remove any previous pending messages, they are no longer current
        self.pending_followup = None;

        // Absorb into state
        self.sync_send_time = Some(
            Instant::from(message.precise_origin_timestamp())
                + Duration::from(message.header().correction_field())
                + self.sync_correction?,
        );
        self.sync_correction = None;

        Some(())
    }

    fn handle_delayresp(&mut self, message: DelayRespMessage) -> Option<()> {
        // Ignore messages not belonging to currently processing sync
        if self.delay_id? != message.header().sequence_id() {
            return None;
        }

        // Absorb into state
        self.delay_recv_time = Some(
            Instant::from(message.receive_timestamp())
                - Duration::from(message.header().correction_field()),
        );

        // Calculate when we should next measure delay
        //  note that sync_recv_time should always be set here, but if it isn't,
        //  taking the default (0) is safe for recovery.
        self.next_delay_measurement = Some(
            self.sync_recv_time.unwrap_or_default()
                + Duration::from_log_interval(message.header().log_message_interval())
                - Duration::from_fixed_nanos(0.1f64),
        );

        self.finish_delay_measurement();

        Some(())
    }

    fn handle_send_timestamp(&mut self, id: usize, timestamp: Instant) -> Option<()> {
        if self.delay_send_id? == id {
            self.delay_send_time = Some(timestamp);
            self.delay_send_id = None;
            self.finish_delay_measurement();
            Some(())
        } else {
            None
        }
    }

    fn finish_delay_measurement(&mut self) -> Option<()> {
        self.mean_delay = Some(
            (self.sync_recv_time? - self.sync_send_time?
                + (self.delay_recv_time? - self.delay_send_time?))
                / 2,
        );

        self.delay_send_time = None;
        self.delay_recv_time = None;
        self.delay_id = None;

        Some(())
    }

    fn extract_measurement(&mut self) -> Option<Measurement> {
        let result = Measurement {
            master_offset: self.sync_recv_time? - self.sync_send_time? - self.mean_delay?,
            event_time: self.sync_recv_time?,
        };

        self.sync_recv_time = None;
        self.sync_send_time = None;
        self.sync_id = None;

        Some(result)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use std::borrow::ToOwned;

    use fixed::traits::ToFixed;

    use crate::datastructures::common::{ClockIdentity, TimeSource};
    use crate::datastructures::datasets::{DelayMechanism, PortDS, TimePropertiesDS};
    use crate::network::test::TestRuntimePort;
    use crate::{
        bmc::bmca::Bmca,
        datastructures::{
            common::{ClockQuality, PortIdentity, TimeInterval, Timestamp},
            messages::MessageBuilder,
        },
        network::{test::TestRuntime, NetworkRuntime},
        port::Measurement,
        time::{Duration, Instant},
    };

    use super::{SequenceIdGenerator, StateSlave};

    fn test_port_data(network_runtime: &mut TestRuntime) -> PortData<TestRuntimePort> {
        let tc_port = network_runtime.open("".to_owned(), true).unwrap();
        let nc_port = network_runtime.open("".to_owned(), false).unwrap();

        let identity = PortIdentity {
            clock_identity: ClockIdentity([1, 0, 0, 0, 0, 0, 0, 0]),
            port_number: 0,
        };

        let port_ds = PortDS::new(identity, 37, 1, 5, 1, DelayMechanism::E2E, 37, 0, 1);

        PortData {
            tc_port,
            nc_port,
            delay_req_ids: SequenceIdGenerator::default(),
            sdo: 0,
            domain: 0,
            port_ds,
            bmca: Bmca::new(TimeInterval(2_000_000_000u64.to_fixed()), identity),
            clock_quality: ClockQuality::default(),
            time_properties: TimePropertiesDS::new_arbitrary(
                false,
                false,
                TimeSource::InternalOscillator,
            ),
            announce_seq_id: 0,
            delay_resp_seq_id: 0,
            follow_up_seq_id: 0,
            sync_seq_id: 0,
        }
    }

    #[test]
    fn test_measurement_flow() {
        let mut network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = test_port_data(&mut network_runtime);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some(Instant::from_nanos(5)),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

        assert_eq!(test_state.extract_measurement(), None);

        let requesting_port_identity = test_port_data.port_ds.port_identity;
        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    requesting_port_identity,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some(Measurement {
                master_offset: Duration::from_nanos(1),
                event_time: Instant::from_nanos(5),
            })
        );
    }

    #[test]
    fn test_measurement_flow_timestamps_out_of_order() {
        let mut network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = test_port_data(&mut network_runtime);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some(Instant::from_nanos(5)),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

        assert_eq!(
            test_state.extract_measurement(),
            Some(Measurement {
                master_offset: Duration::from_nanos(1),
                event_time: Instant::from_nanos(5),
            })
        );
    }

    #[test]
    fn test_measurement_flow_followup() {
        let mut network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = test_port_data(&mut network_runtime);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some(Instant::from_nanos(5)),
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .follow_up_message(Timestamp {
                    seconds: 0,
                    nanos: 1,
                }),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some(Measurement {
                master_offset: Duration::from_nanos(0),
                event_time: Instant::from_nanos(5),
            })
        );
    }

    #[test]
    fn test_measurement_flow_followup_out_of_order() {
        let mut network_runtime = TestRuntime::default();

        let master_id = PortIdentity::default();
        let mut test_id = PortIdentity::default();
        test_id.clock_identity.0[0] += 1;

        let mut test_state = StateSlave {
            remote_master: master_id,
            ..Default::default()
        };

        let mut test_port_data = test_port_data(&mut network_runtime);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .follow_up_message(Timestamp {
                    seconds: 0,
                    nanos: 1,
                }),
            None,
        );

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .two_step_flag(true)
                .correction_field(TimeInterval((1 as i16).to_fixed()))
                .sync_message(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
            Some(Instant::from_nanos(5)),
        );

        assert_eq!(test_state.extract_measurement(), None);

        let delay_req = network_runtime.get_sent().unwrap();
        test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

        assert_eq!(test_state.extract_measurement(), None);

        test_state.handle_message(
            &mut test_port_data,
            MessageBuilder::new()
                .sdo_id(0)
                .unwrap()
                .domain_number(0)
                .correction_field(TimeInterval((2 as i16).to_fixed()))
                .delay_resp_message(
                    Timestamp {
                        seconds: 0,
                        nanos: 11,
                    },
                    test_id,
                ),
            None,
        );

        assert_eq!(
            test_state.extract_measurement(),
            Some(Measurement {
                master_offset: Duration::from_nanos(0),
                event_time: Instant::from_nanos(5),
            })
        );
    }
}
