use rand::Rng;

use crate::{
    datastructures::{
        common::PortIdentity,
        datasets::DefaultDS,
        messages::{DelayRespMessage, FollowUpMessage, Header, Message, MessageBody, SyncMessage},
    },
    port::{
        sequence_id::SequenceIdGenerator, Measurement, PortAction, PortActionIterator,
        TimestampContext, TimestampContextInner,
    },
    time::{Duration, Time},
    Clock, DelayMechanism, Filter, PortConfig,
};

#[derive(Debug)]
pub(crate) struct SlaveState<F> {
    remote_master: PortIdentity,

    sync_state: SyncState,
    delay_state: DelayState,

    mean_delay: Option<Duration>,
    last_raw_sync_offset: Option<Duration>,

    delay_req_ids: SequenceIdGenerator,

    filter: F,
}

impl<F> SlaveState<F> {
    pub(crate) fn remote_master(&self) -> PortIdentity {
        self.remote_master
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncState {
    Empty,
    Measuring {
        id: u16,
        send_time: Option<Time>,
        recv_time: Option<Time>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelayState {
    Empty,
    Measuring {
        id: u16,
        send_time: Option<Time>,
        recv_time: Option<Time>,
    },
}

impl<F: Filter> SlaveState<F> {
    pub(crate) fn new(remote_master: PortIdentity, filter_config: F::Config) -> Self {
        SlaveState {
            remote_master,
            sync_state: SyncState::Empty,
            delay_state: DelayState::Empty,
            mean_delay: None,
            last_raw_sync_offset: None,
            delay_req_ids: SequenceIdGenerator::new(),
            filter: F::new(filter_config),
        }
    }

    fn handle_time_measurement<'a, C: Clock>(&mut self, clock: &mut C) -> PortActionIterator<'a> {
        if let Some(measurement) = self.extract_measurement() {
            // If the received message allowed the (slave) state to calculate its offset
            // from the master, update the local clock
            let filter_updates = self.filter.measurement(measurement, clock);
            if let Some(mean_delay) = filter_updates.mean_delay {
                self.mean_delay = Some(mean_delay);
            }
            PortActionIterator::from_filter(filter_updates)
        } else {
            actions![]
        }
    }

    pub(crate) fn handle_timestamp<'a, C: Clock>(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
        clock: &mut C,
    ) -> PortActionIterator<'a> {
        match context.inner {
            crate::port::TimestampContextInner::DelayReq { id } => {
                // handle our send timestamp on a delay request message
                self.handle_delay_timestamp(id, timestamp, clock)
            }
            _ => {
                log::error!("Unexpected timestamp");
                actions![]
            }
        }
    }

    fn handle_delay_timestamp<'a, C: Clock>(
        &mut self,
        timestamp_id: u16,
        timestamp: Time,
        clock: &mut C,
    ) -> PortActionIterator<'a> {
        match self.delay_state {
            DelayState::Measuring {
                id,
                send_time: Some(_),
                ..
            } if id == timestamp_id => {
                log::error!("Double send timestamp for delay request");
                actions![]
            }
            DelayState::Measuring {
                id,
                ref mut send_time,
                ..
            } if id == timestamp_id => {
                *send_time = Some(timestamp);
                self.handle_time_measurement(clock)
            }
            _ => {
                log::warn!("Late timestamp for delay request ignored");
                actions![]
            }
        }
    }

    pub(crate) fn handle_event_receive<'a, C: Clock>(
        &mut self,
        message: Message,
        timestamp: Time,
        clock: &mut C,
    ) -> PortActionIterator<'a> {
        // Ignore everything not from master
        let header = &message.header;

        if header.source_port_identity != self.remote_master {
            return actions![];
        }

        match message.body {
            MessageBody::Sync(sync) => self.handle_sync(header, sync, timestamp, clock),
            _ => {
                log::warn!("Unexpected message {:?}", message);
                actions![]
            }
        }
    }

    pub(crate) fn handle_general_receive<C: Clock>(
        &mut self,
        message: Message,
        port_identity: PortIdentity,
        clock: &mut C,
    ) -> PortActionIterator {
        let header = &message.header;

        // Ignore everything not from master
        if header.source_port_identity != self.remote_master {
            return actions![];
        }

        match message.body {
            MessageBody::FollowUp(message) => self.handle_follow_up(header, message, clock),
            MessageBody::DelayResp(message) => {
                self.handle_delay_resp(header, message, port_identity, clock)
            }
            _ => {
                log::warn!("Unexpected message {:?}", message);
                actions![]
            }
        }
    }

    pub(crate) fn handle_filter_update<'a, C: Clock>(
        &mut self,
        clock: &mut C,
    ) -> PortActionIterator<'a> {
        PortActionIterator::from_filter(self.filter.update(clock))
    }

    pub(crate) fn demobilize_filter<C: Clock>(self, clock: &mut C) {
        self.filter.demobilize(clock);
    }

    fn handle_sync<'a, C: Clock>(
        &mut self,
        header: &Header,
        message: SyncMessage,
        recv_time: Time,
        clock: &mut C,
    ) -> PortActionIterator<'a> {
        log::debug!("Received sync {:?}", header.sequence_id);

        // substracting correction from recv time is equivalent to adding it to send
        // time
        let corrected_recv_time = recv_time - Duration::from(header.correction_field);

        if header.two_step_flag {
            match self.sync_state {
                SyncState::Measuring {
                    id,
                    recv_time: Some(_),
                    ..
                } if id == header.sequence_id => {
                    log::warn!("Duplicate sync message");
                    // Ignore the sync message
                    actions![]
                }
                SyncState::Measuring {
                    id,
                    ref mut recv_time,
                    ..
                } if id == header.sequence_id => {
                    *recv_time = Some(corrected_recv_time);
                    self.handle_time_measurement(clock)
                }
                _ => {
                    self.sync_state = SyncState::Measuring {
                        id: header.sequence_id,
                        send_time: None,
                        recv_time: Some(corrected_recv_time),
                    };
                    actions![]
                }
            }
        } else {
            match self.sync_state {
                SyncState::Measuring { id, .. } if id == header.sequence_id => {
                    log::warn!("Duplicate sync message");
                    // Ignore the sync message
                    actions![]
                }
                _ => {
                    self.sync_state = SyncState::Measuring {
                        id: header.sequence_id,
                        send_time: Some(Time::from(message.origin_timestamp)),
                        recv_time: Some(corrected_recv_time),
                    };
                    self.handle_time_measurement(clock)
                }
            }
        }
    }

    fn handle_follow_up<C: Clock>(
        &mut self,
        header: &Header,
        message: FollowUpMessage,
        clock: &mut C,
    ) -> PortActionIterator {
        log::debug!("Received FollowUp {:?}", header.sequence_id);

        let packet_send_time =
            Time::from(message.precise_origin_timestamp) + Duration::from(header.correction_field);

        match self.sync_state {
            SyncState::Measuring {
                id,
                send_time: Some(_),
                ..
            } if id == header.sequence_id => {
                log::warn!("Duplicate FollowUp message");
                // Ignore the followup
                actions![]
            }
            SyncState::Measuring {
                id,
                ref mut send_time,
                ..
            } if id == header.sequence_id => {
                *send_time = Some(packet_send_time);
                self.handle_time_measurement(clock)
            }
            _ => {
                self.sync_state = SyncState::Measuring {
                    id: header.sequence_id,
                    send_time: Some(packet_send_time),
                    recv_time: None,
                };
                self.handle_time_measurement(clock)
            }
        }
    }

    fn handle_delay_resp<C: Clock>(
        &mut self,
        header: &Header,
        message: DelayRespMessage,
        port_identity: PortIdentity,
        clock: &mut C,
    ) -> PortActionIterator {
        log::debug!("Received DelayResp");
        if port_identity != message.requesting_port_identity {
            return actions![];
        }

        match self.delay_state {
            DelayState::Measuring {
                id,
                recv_time: Some(_),
                ..
            } if id == header.sequence_id => {
                log::warn!("Duplicate DelayResp message");
                // Ignore the Delay response
                actions![]
            }
            DelayState::Measuring {
                id,
                ref mut recv_time,
                ..
            } if id == header.sequence_id => {
                *recv_time = Some(
                    Time::from(message.receive_timestamp) - Duration::from(header.correction_field),
                );
                self.handle_time_measurement(clock)
            }
            _ => {
                log::warn!("Unexpected DelayResp message");
                // Ignore the Delay response
                actions![]
            }
        }
    }
}

impl<F> SlaveState<F> {
    pub(crate) fn send_delay_request<'a>(
        &mut self,
        rng: &mut impl Rng,
        port_config: &PortConfig<()>,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::debug!("Starting new delay measurement");

        let delay_id = self.delay_req_ids.generate();
        let delay_req = Message::delay_req(default_ds, port_identity, delay_id);

        let message_length = match delay_req.serialize(buffer) {
            Ok(length) => length,
            Err(error) => {
                log::error!("Could not serialize delay request: {:?}", error);
                return actions![];
            }
        };

        self.delay_state = DelayState::Measuring {
            id: delay_id,
            send_time: None,
            recv_time: None,
        };

        let random = rng.sample::<f64, _>(rand::distributions::Open01);
        let log_min_delay_req_interval = match port_config.delay_mechanism {
            // the interval corresponds to the PortDS logMinDelayReqInterval
            DelayMechanism::E2E { interval } => interval,
        };
        let factor = random * 2.0f64;
        let duration = log_min_delay_req_interval
            .as_core_duration()
            .mul_f64(factor);

        actions![
            PortAction::ResetDelayRequestTimer { duration },
            PortAction::SendTimeCritical {
                context: TimestampContext {
                    inner: TimestampContextInner::DelayReq { id: delay_id },
                },
                data: &buffer[..message_length],
            }
        ]
    }

    fn extract_measurement(&mut self) -> Option<Measurement> {
        let mut result = Measurement::default();

        if let SyncState::Measuring {
            send_time: Some(send_time),
            recv_time: Some(recv_time),
            ..
        } = self.sync_state
        {
            let raw_sync_offset = recv_time - send_time;
            result.event_time = recv_time;
            result.raw_sync_offset = Some(raw_sync_offset);

            if let Some(mean_delay) = self.mean_delay {
                result.offset = Some(raw_sync_offset - mean_delay);
            }

            self.last_raw_sync_offset = Some(raw_sync_offset);
            self.sync_state = SyncState::Empty;
        } else if let DelayState::Measuring {
            send_time: Some(send_time),
            recv_time: Some(recv_time),
            ..
        } = self.delay_state
        {
            let raw_delay_offset = send_time - recv_time;
            result.event_time = send_time;
            result.raw_delay_offset = Some(raw_delay_offset);

            if let Some(raw_sync_offset) = self.last_raw_sync_offset {
                result.delay = Some((raw_sync_offset - raw_delay_offset) / 2);
            }

            self.delay_state = DelayState::Empty;
        } else {
            // No measurement
            return None;
        }

        log::info!("Measurement: {:?}", result);

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::InstanceConfig,
        datastructures::{
            common::{ClockIdentity, TimeInterval, TlvSet},
            messages::{Header, SdoId},
        },
        filters::FilterUpdate,
        Interval, MAX_DATA_LEN,
    };

    struct TestFilter {
        last_measurement: Option<Measurement>,
    }

    impl Filter for TestFilter {
        type Config = ();

        fn new(_config: Self::Config) -> Self {
            Self {
                last_measurement: None,
            }
        }

        fn measurement<C: Clock>(&mut self, m: Measurement, _clock: &mut C) -> FilterUpdate {
            self.last_measurement = Some(m);
            if let Some(delay) = m.delay {
                FilterUpdate {
                    next_update: None,
                    mean_delay: Some(delay),
                }
            } else {
                Default::default()
            }
        }

        fn demobilize<C: Clock>(self, _clock: &mut C) {
            Default::default()
        }

        fn update<C: Clock>(&mut self, _clock: &mut C) -> FilterUpdate {
            Default::default()
        }
    }

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

    #[test]
    fn test_sync_without_delay_msg() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());
        state.mean_delay = Some(Duration::from_micros(100));

        let header = Header {
            two_step_flag: false,
            correction_field: TimeInterval(1000.into()),
            ..Default::default()
        };

        let body = MessageBody::Sync(SyncMessage {
            origin_timestamp: Time::from_micros(0).into(),
        });

        let mut action = state.handle_event_receive(
            Message {
                header,
                body,
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                offset: Some(Duration::from_micros(-51)),
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(49)),
                raw_delay_offset: None,
            })
        );

        let header = Header {
            two_step_flag: true,
            sequence_id: 15,
            correction_field: TimeInterval(1000.into()),
            ..Default::default()
        };

        let mut action = state.handle_event_receive(
            Message {
                header,
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(1050),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let header = Header {
            sequence_id: 15,
            correction_field: TimeInterval(2000.into()),
            ..Default::default()
        };

        let mut action = state.handle_general_receive(
            Message {
                header,
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(1000).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                offset: Some(Duration::from_micros(-53)),
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(47)),
                raw_delay_offset: None,
            })
        );
    }

    #[test]
    fn test_sync_with_delay() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());

        let mut buffer = [0u8; MAX_DATA_LEN];
        let default_ds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        // mock rng and port config
        let mut rng = rand::rngs::mock::StepRng::new(2, 1);
        let port_identity = Default::default();
        let port_config = PortConfig {
            acceptable_master_list: (),
            delay_mechanism: DelayMechanism::E2E {
                interval: Interval::ONE_SECOND,
            },
            announce_interval: Interval::ONE_SECOND,
            announce_receipt_timeout: Default::default(),
            sync_interval: Interval::ONE_SECOND,
            master_only: Default::default(),
            delay_asymmetry: Default::default(),
        };

        let header = Header {
            two_step_flag: false,
            correction_field: TimeInterval(1000.into()),
            ..Default::default()
        };

        let mut action = state.handle_event_receive(
            Message {
                header,
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                offset: None,
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(49)),
                raw_delay_offset: None,
            })
        );

        let mut action = state.send_delay_request(
            &mut rng,
            &port_config,
            port_identity,
            &default_ds,
            &mut buffer,
        );

        let Some(PortAction::ResetDelayRequestTimer { .. }) = action.next() else {
            panic!("Unexpected action");
        };

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };
        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.filter.last_measurement.take(), None);

        let req = Message::deserialize(data).unwrap();
        let req_header = req.header;

        let _req = match req.body {
            MessageBody::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        let mut action = state.handle_timestamp(context, Time::from_micros(100), &mut TestClock);
        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.filter.last_measurement.take(), None);

        let header = Header {
            correction_field: TimeInterval(2000.into()),
            sequence_id: req_header.sequence_id,
            ..Default::default()
        };

        let body = MessageBody::DelayResp(DelayRespMessage {
            receive_timestamp: Time::from_micros(253).into(),
            requesting_port_identity: req_header.source_port_identity,
        });

        let mut action = state.handle_general_receive(
            Message {
                header,
                body,
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(100),
                offset: None,
                delay: Some(Duration::from_micros(100)),
                raw_sync_offset: None,
                raw_delay_offset: Some(Duration::from_micros(-151)),
            })
        );

        state.mean_delay = None;

        let header = Header {
            two_step_flag: true,
            correction_field: TimeInterval(1000.into()),
            ..Default::default()
        };

        let mut action = state.handle_event_receive(
            Message {
                header,
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(1050),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.send_delay_request(
            &mut rng,
            &port_config,
            port_identity,
            &default_ds,
            &mut buffer,
        );

        let Some(PortAction::ResetDelayRequestTimer { .. }) = action.next() else {
            panic!("Unexpected action");
        };

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };
        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.filter.last_measurement.take(), None);

        let req = Message::deserialize(data).unwrap();
        let req_header = req.header;

        let _req = match req.body {
            MessageBody::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        let mut action = state.handle_timestamp(context, Time::from_micros(1100), &mut TestClock);
        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(1000).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                offset: None,
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(47)),
                raw_delay_offset: None,
            })
        );

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req_header.sequence_id,
                    ..Default::default()
                },
                body: MessageBody::DelayResp(DelayRespMessage {
                    receive_timestamp: Time::from_micros(1255).into(),
                    requesting_port_identity: req_header.source_port_identity,
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(1100),
                offset: None,
                delay: Some(Duration::from_micros(100)),
                raw_sync_offset: None,
                raw_delay_offset: Some(Duration::from_micros(-153)),
            })
        );
    }

    #[test]
    fn test_follow_up_before_sync() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());
        state.mean_delay = Some(Duration::from_micros(100));

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(10).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                offset: Some(Duration::from_micros(-63)),
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(37)),
                raw_delay_offset: None,
            })
        );
    }

    #[test]
    fn test_old_followup_during() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());
        state.mean_delay = Some(Duration::from_micros(100));

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    sequence_id: 14,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(10).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(10).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.filter.last_measurement.take(), None);
    }

    #[test]
    fn test_reset_after_missing_followup() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());
        state.mean_delay = Some(Duration::from_micros(100));

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 14,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(1050),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                body: MessageBody::FollowUp(FollowUpMessage {
                    precise_origin_timestamp: Time::from_micros(1000).into(),
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                offset: Some(Duration::from_micros(-53)),
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(47)),
                raw_delay_offset: None,
            })
        );
    }

    #[test]
    fn test_ignore_unrelated_delayresp() {
        let mut state = SlaveState::<TestFilter>::new(Default::default(), ());
        let mut buffer = [0u8; MAX_DATA_LEN];

        let default_ds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        // mock rng and port config
        let mut rng = rand::rngs::mock::StepRng::new(2, 1);
        let port_identity = Default::default();
        let port_config = PortConfig {
            acceptable_master_list: (),
            delay_mechanism: DelayMechanism::E2E {
                interval: Interval::ONE_SECOND,
            },
            announce_interval: Interval::ONE_SECOND,
            announce_receipt_timeout: Default::default(),
            sync_interval: Interval::ONE_SECOND,
            master_only: Default::default(),
            delay_asymmetry: Default::default(),
        };

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                body: MessageBody::Sync(SyncMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_micros(50),
            &mut TestClock,
        );

        // DelayReq is sent independently
        assert!(action.next().is_none());
        drop(action);
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                offset: None,
                delay: None,
                raw_sync_offset: Some(Duration::from_micros(49)),
                raw_delay_offset: None,
            })
        );

        let mut action = state.send_delay_request(
            &mut rng,
            &port_config,
            port_identity,
            &default_ds,
            &mut buffer,
        );

        let Some(PortAction::ResetDelayRequestTimer { .. }) = action.next() else {
            panic!("Unexpected action");
        };

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };

        let mut action = state.handle_timestamp(context, Time::from_micros(100), &mut TestClock);

        assert!(action.next().is_none());
        assert_eq!(state.filter.last_measurement.take(), None);

        let req = Message::deserialize(data).unwrap();
        let req_header = req.header;

        let _req = match req.body {
            MessageBody::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req_header.sequence_id,
                    ..Default::default()
                },
                body: MessageBody::DelayResp(DelayRespMessage {
                    receive_timestamp: Time::from_micros(353).into(),
                    requesting_port_identity: PortIdentity {
                        port_number: 83,
                        ..Default::default()
                    },
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req_header.sequence_id.wrapping_sub(1),
                    ..Default::default()
                },
                body: MessageBody::DelayResp(DelayRespMessage {
                    receive_timestamp: Time::from_micros(353).into(),
                    requesting_port_identity: req_header.source_port_identity,
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.filter.last_measurement.take(), None);

        let mut action = state.handle_general_receive(
            Message {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req_header.sequence_id,
                    ..Default::default()
                },
                body: MessageBody::DelayResp(DelayRespMessage {
                    receive_timestamp: Time::from_micros(253).into(),
                    requesting_port_identity: req_header.source_port_identity,
                }),
                suffix: TlvSet::default(),
            },
            PortIdentity::default(),
            &mut TestClock,
        );

        assert!(action.next().is_none());
        drop(action);

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.filter.last_measurement.take(),
            Some(Measurement {
                event_time: Time::from_micros(100),
                offset: None,
                delay: Some(Duration::from_micros(100)),
                raw_sync_offset: None,
                raw_delay_offset: Some(Duration::from_micros(-151)),
            })
        );
    }
}
