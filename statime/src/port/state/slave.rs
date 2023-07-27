use crate::{
    datastructures::{
        common::{PortIdentity, WireTimestamp},
        datasets::DefaultDS,
        messages::{DelayRespMessage, FollowUpMessage, Message, MessageBuilder, SyncMessage},
    },
    port::{
        sequence_id::SequenceIdGenerator, Measurement, PortAction, PortActionIterator,
        TimestampContext, TimestampContextInner,
    },
    time::{Duration, Interval, Time},
};

#[derive(Debug)]
pub struct SlaveState {
    remote_master: PortIdentity,

    sync_state: SyncState,
    delay_state: DelayState,

    mean_delay: Option<Duration>,
    last_raw_offset: Option<Duration>,

    delay_req_ids: SequenceIdGenerator,

    next_delay_measurement: Option<Time>,
}

impl SlaveState {
    pub fn remote_master(&self) -> PortIdentity {
        self.remote_master
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SyncState {
    Empty,
    Measuring {
        id: u16,
        send_time: Option<Time>,
        recv_time: Option<Time>,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum DelayState {
    Empty,
    Measuring {
        id: u16,
        send_time: Option<Time>,
        recv_time: Option<Time>,
    },
}

impl SlaveState {
    pub fn new(remote_master: PortIdentity) -> Self {
        SlaveState {
            remote_master,
            sync_state: SyncState::Empty,
            delay_state: DelayState::Empty,
            mean_delay: None,
            last_raw_offset: None,
            delay_req_ids: SequenceIdGenerator::new(),
            next_delay_measurement: None,
        }
    }

    pub(crate) fn handle_timestamp<'a>(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
    ) -> PortActionIterator<'a> {
        match context.inner {
            crate::port::TimestampContextInner::DelayReq { id } => {
                // handle our send timestamp on a delay request message
                self.handle_delay_timestamp(id, timestamp)
            }
            _ => {
                log::error!("Unexpected timestamp");
                actions![]
            }
        }
    }

    fn handle_delay_timestamp<'a>(
        &mut self,
        timestamp_id: u16,
        timestamp: Time,
    ) -> PortActionIterator<'a> {
        match self.delay_state {
            DelayState::Measuring {
                id,
                send_time: Some(_),
                ..
            } if id == timestamp_id => {
                log::error!("Double send timestamp for delay request");
            }
            DelayState::Measuring {
                id,
                ref mut send_time,
                ..
            } if id == timestamp_id => *send_time = Some(timestamp),
            _ => {
                log::warn!("Late timestamp for delay request ignored");
            }
        }

        actions![]
    }

    pub(crate) fn handle_event_receive<'a>(
        &mut self,
        message: Message,
        timestamp: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        // Ignore everything not from master
        if message.header().source_port_identity() != self.remote_master {
            return actions![];
        }

        match message {
            Message::Sync(message) => {
                self.handle_sync(message, timestamp, port_identity, default_ds, buffer)
            }
            _ => {
                log::warn!("Unexpected message {:?}", message);
                actions![]
            }
        }
    }

    pub(crate) fn handle_general_receive(&mut self, message: Message, port_identity: PortIdentity) {
        // Ignore everything not from master
        if message.header().source_port_identity() != self.remote_master {
            return;
        }

        match message {
            Message::FollowUp(message) => self.handle_follow_up(message),
            Message::DelayResp(message) => self.handle_delay_resp(message, port_identity),
            _ => log::warn!("Unexpected message {:?}", message),
        }
    }

    fn update_last_raw_offset(&mut self) {
        if let SyncState::Measuring {
            send_time: Some(send_time),
            recv_time: Some(recv_time),
            ..
        } = self.sync_state
        {
            self.last_raw_offset = Some(recv_time - send_time);
            self.try_finish_delay_measurement();
        }
    }

    fn handle_sync<'a>(
        &mut self,
        message: SyncMessage,
        recv_time: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::debug!("Received sync {:?}", message.header().sequence_id());

        // substracting correction from recv time is equivalent to adding it to send
        // time
        let corrected_recv_time = recv_time - Duration::from(message.header().correction_field());

        if message.header().two_step_flag() {
            match self.sync_state {
                SyncState::Measuring {
                    id,
                    recv_time: Some(_),
                    ..
                } if id == message.header().sequence_id() => {
                    log::warn!("Duplicate sync message");
                    // Ignore the sync message
                }
                SyncState::Measuring {
                    id,
                    ref mut recv_time,
                    ..
                } if id == message.header().sequence_id() => *recv_time = Some(corrected_recv_time),
                _ => {
                    self.sync_state = SyncState::Measuring {
                        id: message.header().sequence_id(),
                        send_time: None,
                        recv_time: Some(corrected_recv_time),
                    }
                }
            }
        } else {
            match self.sync_state {
                SyncState::Measuring { id, .. } if id == message.header().sequence_id() => {
                    log::warn!("Duplicate sync message");
                    // Ignore the sync message
                }
                _ => {
                    self.sync_state = SyncState::Measuring {
                        id: message.header().sequence_id(),
                        send_time: Some(Time::from(message.origin_timestamp)),
                        recv_time: Some(corrected_recv_time),
                    };
                }
            }
        }

        self.update_last_raw_offset();

        if self.mean_delay.is_none() || self.next_delay_measurement.unwrap_or_default() < recv_time
        {
            log::debug!("Starting new delay measurement");
            let delay_id = self.delay_req_ids.generate();
            let delay_req = MessageBuilder::new()
                .sdo_id(default_ds.sdo_id)
                .domain_number(default_ds.domain_number)
                .source_port_identity(port_identity)
                .sequence_id(delay_id)
                .message_interval(Interval::from_log_2(0x7f))
                .delay_req_message(WireTimestamp::default());
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
            actions![PortAction::SendTimeCritical {
                context: TimestampContext {
                    inner: TimestampContextInner::DelayReq { id: delay_id },
                },
                data: &buffer[..message_length],
            }]
        } else {
            actions![]
        }
    }

    fn handle_follow_up(&mut self, message: FollowUpMessage) {
        log::debug!("Received FollowUp {:?}", message.header().sequence_id());

        let packet_send_time = Time::from(message.precise_origin_timestamp())
            + Duration::from(message.header().correction_field());

        match self.sync_state {
            SyncState::Measuring {
                id,
                send_time: Some(_),
                ..
            } if id == message.header().sequence_id() => {
                log::warn!("Duplicate FollowUp message");
                // Ignore the followup
            }
            SyncState::Measuring {
                id,
                ref mut send_time,
                ..
            } if id == message.header().sequence_id() => *send_time = Some(packet_send_time),
            _ => {
                self.sync_state = SyncState::Measuring {
                    id: message.header().sequence_id(),
                    send_time: Some(packet_send_time),
                    recv_time: None,
                }
            }
        }

        self.update_last_raw_offset();
    }

    fn try_finish_delay_measurement(&mut self) {
        if let (
            DelayState::Measuring {
                send_time: Some(send_time),
                recv_time: Some(recv_time),
                ..
            },
            Some(last_raw_offset),
        ) = (&self.delay_state, self.last_raw_offset)
        {
            self.mean_delay = Some(((*recv_time - *send_time) + last_raw_offset) / 2);
            self.delay_state = DelayState::Empty;
        }
    }

    fn handle_delay_resp(&mut self, message: DelayRespMessage, port_identity: PortIdentity) {
        log::debug!("Received DelayResp");
        if port_identity != message.requesting_port_identity() {
            return;
        }

        match self.delay_state {
            DelayState::Measuring {
                id,
                recv_time: Some(_),
                ..
            } if id == message.header().sequence_id() => {
                log::warn!("Duplicate DelayResp message");
                // Ignore the Delay response
            }
            DelayState::Measuring {
                id,
                ref mut recv_time,
                ..
            } if id == message.header().sequence_id() => {
                *recv_time = Some(
                    Time::from(message.receive_timestamp())
                        - Duration::from(message.header().correction_field()),
                );
                self.next_delay_measurement = Some(
                    *recv_time.as_ref().unwrap()
                        + Duration::from_log_interval(message.header().log_message_interval())
                        - Duration::from_fixed_nanos(0.1f64),
                );
            }
            _ => {
                log::warn!("Unexpected DelayResp message");
                // Ignore the Delay response
            }
        }

        self.try_finish_delay_measurement();
    }

    pub(crate) fn extract_measurement(&mut self) -> Option<Measurement> {
        match (&self.sync_state, self.mean_delay) {
            (
                SyncState::Measuring {
                    send_time: Some(send_time),
                    recv_time: Some(recv_time),
                    ..
                },
                Some(mean_delay),
            ) => {
                let result = Measurement {
                    master_offset: *recv_time - *send_time - mean_delay,
                    event_time: *recv_time,
                };

                self.sync_state = SyncState::Empty;

                log::debug!("Extracted measurement {:?}", result);

                Some(result)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::InstanceConfig,
        datastructures::{
            common::{ClockIdentity, TimeInterval},
            messages::{Header, SdoId},
        },
        MAX_DATA_LEN,
    };

    #[test]
    fn test_sync_without_delay_msg() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());
        state.mean_delay = Some(Duration::from_micros(100));
        state.next_delay_measurement = Some(Time::from_secs(10));

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        drop(action);
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                master_offset: Duration::from_micros(-51)
            })
        );

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(1050),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(1000).into(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_sync_with_delay() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };
        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.extract_measurement(), None);

        let req = match Message::deserialize(data).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        let mut action = state.handle_timestamp(context, Time::from_micros(100));
        assert!(action.next().is_none());
        drop(action);

        state.handle_general_receive(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Time::from_micros(253).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                master_offset: Duration::from_micros(-51)
            })
        );

        state.mean_delay = None;

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(1050),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };
        assert!(action.next().is_none());
        drop(action);

        let req = match Message::deserialize(data).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        let mut action = state.handle_timestamp(context, Time::from_micros(1100));
        assert!(action.next().is_none());

        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(1000).into(),
            }),
            PortIdentity::default(),
        );

        state.handle_general_receive(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Time::from_micros(1255).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_follow_up_before_sync() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());
        state.mean_delay = Some(Duration::from_micros(100));
        state.next_delay_measurement = Some(Time::from_secs(10));

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(10).into(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.extract_measurement(), None);

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                master_offset: Duration::from_micros(-63)
            })
        );
    }

    #[test]
    fn test_old_followup_during() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());
        state.mean_delay = Some(Duration::from_micros(100));
        state.next_delay_measurement = Some(Time::from_secs(10));

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 14,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(10).into(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(10).into(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.extract_measurement(), None);
    }

    #[test]
    fn test_reset_after_missing_followup() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());
        state.mean_delay = Some(Duration::from_micros(100));
        state.next_delay_measurement = Some(Time::from_secs(10));

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 14,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        drop(action);
        assert_eq!(state.extract_measurement(), None);

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: true,
                    sequence_id: 15,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(1050),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        assert!(action.next().is_none());
        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::FollowUp(FollowUpMessage {
                header: Header {
                    sequence_id: 15,
                    correction_field: TimeInterval(2000.into()),
                    ..Default::default()
                },
                precise_origin_timestamp: Time::from_micros(1000).into(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(1049),
                master_offset: Duration::from_micros(-53)
            })
        );
    }

    #[test]
    fn test_ignore_unrelated_delayresp() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut state = SlaveState::new(Default::default());

        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut action = state.handle_event_receive(
            Message::Sync(SyncMessage {
                header: Header {
                    two_step_flag: false,
                    correction_field: TimeInterval(1000.into()),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_micros(50),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendTimeCritical { context, data }) = action.next() else {
            panic!("Unexpected action");
        };
        assert!(action.next().is_none());

        let mut action = state.handle_timestamp(context, Time::from_micros(100));
        assert!(action.next().is_none());

        assert_eq!(state.extract_measurement(), None);

        let req = match Message::deserialize(&data).unwrap() {
            Message::DelayReq(msg) => msg,
            _ => panic!("Incorrect message type"),
        };

        state.handle_general_receive(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Time::from_micros(353).into(),
                requesting_port_identity: PortIdentity {
                    port_number: 83,
                    ..Default::default()
                },
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id.wrapping_sub(1),
                    ..Default::default()
                },
                receive_timestamp: Time::from_micros(353).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.extract_measurement(), None);

        state.handle_general_receive(
            Message::DelayResp(DelayRespMessage {
                header: Header {
                    correction_field: TimeInterval(2000.into()),
                    sequence_id: req.header.sequence_id,
                    ..Default::default()
                },
                receive_timestamp: Time::from_micros(253).into(),
                requesting_port_identity: req.header.source_port_identity(),
            }),
            PortIdentity::default(),
        );

        assert_eq!(state.mean_delay, Some(Duration::from_micros(100)));
        assert_eq!(
            state.extract_measurement(),
            Some(Measurement {
                event_time: Time::from_micros(49),
                master_offset: Duration::from_micros(-51)
            })
        );
    }
}
