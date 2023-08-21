use core::fmt::Debug;

use crate::{
    datastructures::{
        common::PortIdentity,
        datasets::DefaultDS,
        messages::{DelayReqMessage, Header, Message, MessageBody},
    },
    port::{
        sequence_id::SequenceIdGenerator, PortAction, PortActionIterator, TimestampContext,
        TimestampContextInner,
    },
    ptp_instance::PtpInstanceState,
    time::{Interval, Time},
    PortConfig,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MasterState {
    pub(in crate::port) announce_seq_ids: SequenceIdGenerator,
    pub(in crate::port) sync_seq_ids: SequenceIdGenerator,
}

impl MasterState {
    pub(crate) fn new() -> Self {
        MasterState {
            announce_seq_ids: SequenceIdGenerator::new(),
            sync_seq_ids: SequenceIdGenerator::new(),
        }
    }

    pub(crate) fn handle_timestamp<'a>(
        &mut self,
        context: TimestampContext,
        timestamp: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        match context.inner {
            TimestampContextInner::Sync { id } => {
                self.handle_sync_timestamp(id, timestamp, port_identity, default_ds, buffer)
            }
            _ => {
                log::error!("Unexpected send timestamp");
                actions![]
            }
        }
    }

    pub(crate) fn handle_sync_timestamp<'a>(
        &mut self,
        id: u16,
        timestamp: Time,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        let packet_length =
            match Message::follow_up(default_ds, port_identity, id, timestamp).serialize(buffer) {
                Ok(length) => length,
                Err(error) => {
                    log::error!(
                        "Statime bug: Could not serialize sync follow up {:?}",
                        error
                    );
                    return actions![];
                }
            };

        actions![PortAction::SendGeneral {
            data: &buffer[..packet_length],
        }]
    }

    pub(crate) fn send_sync<'a>(
        &mut self,
        config: &PortConfig,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::trace!("sending sync message");

        let seq_id = self.sync_seq_ids.generate();
        let packet_length = match Message::sync(default_ds, port_identity, seq_id).serialize(buffer)
        {
            Ok(message) => message,
            Err(error) => {
                log::error!("Statime bug: Could not serialize sync: {:?}", error);
                return actions![];
            }
        };

        actions![
            PortAction::ResetSyncTimer {
                duration: config.sync_interval.as_core_duration(),
            },
            PortAction::SendTimeCritical {
                context: TimestampContext {
                    inner: TimestampContextInner::Sync { id: seq_id },
                },
                data: &buffer[..packet_length],
            }
        ]
    }

    pub(crate) fn send_announce<'a>(
        &mut self,
        global: &PtpInstanceState,
        config: &PortConfig,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::trace!("sending announce message");

        let packet_length =
            match Message::announce(global, port_identity, self.announce_seq_ids.generate())
                .serialize(buffer)
            {
                Ok(length) => length,
                Err(error) => {
                    log::error!(
                        "Statime bug: Could not serialize announce message {:?}",
                        error
                    );
                    return actions![];
                }
            };

        actions![
            PortAction::ResetAnnounceTimer {
                duration: config.announce_interval.as_core_duration(),
            },
            PortAction::SendGeneral {
                data: &buffer[..packet_length]
            }
        ]
    }

    pub(crate) fn handle_event_receive<'a>(
        &mut self,
        message: Message,
        timestamp: Time,
        min_delay_req_interval: Interval,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        let header = message.header;

        if header.source_port_identity == port_identity {
            return actions![];
        }

        match message.body {
            MessageBody::DelayReq(message) => self.handle_delay_req(
                header,
                message,
                timestamp,
                min_delay_req_interval,
                port_identity,
                buffer,
            ),
            _ => {
                log::warn!("Unexpected message {:?}", message);
                actions![]
            }
        }
    }

    fn handle_delay_req<'a>(
        &mut self,
        header: Header,
        message: DelayReqMessage,
        timestamp: Time,
        min_delay_req_interval: Interval,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::debug!("Received DelayReq");
        let delay_resp_message = Message::delay_resp(
            header,
            message,
            port_identity,
            min_delay_req_interval,
            timestamp,
        );

        let packet_length = match delay_resp_message.serialize(buffer) {
            Ok(length) => length,
            Err(error) => {
                log::error!("Could not serialize delay response: {:?}", error);
                return actions![];
            }
        };

        actions![PortAction::SendGeneral {
            data: &buffer[..packet_length],
        }]
    }
}

#[cfg(test)]
mod tests {
    use fixed::types::{I48F16, U96F32};

    use super::*;
    use crate::{
        config::InstanceConfig,
        datastructures::{
            common::{ClockIdentity, TimeInterval, TlvSet},
            datasets::{CurrentDS, ParentDS},
            messages::{Header, SdoId},
        },
        time::Interval,
        Duration, TimePropertiesDS, MAX_DATA_LEN,
    };

    #[test]
    fn test_delay_response() {
        let mut state = MasterState::new();

        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    sequence_id: 5123,
                    source_port_identity: PortIdentity {
                        port_number: 83,
                        ..Default::default()
                    },
                    correction_field: TimeInterval(I48F16::from_bits(400)),
                    ..Default::default()
                },
                body: MessageBody::DelayReq(DelayReqMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_fixed_nanos(U96F32::from_bits((200000 << 32) + (500 << 16))),
            Interval::from_log_2(2),
            PortIdentity::default(),
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = action.next() else {
            panic!("Unexpected resulting action");
        };
        assert!(action.next().is_none());
        drop(action);

        let msg = Message::deserialize(data).unwrap();
        let msg_header = msg.header;

        let msg = match msg.body {
            MessageBody::DelayResp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(
            msg.requesting_port_identity,
            PortIdentity {
                port_number: 83,
                ..Default::default()
            }
        );
        assert_eq!(msg_header.sequence_id, 5123);
        assert_eq!(msg.receive_timestamp, Time::from_micros(200).into());
        assert_eq!(msg_header.log_message_interval, 2);
        assert_eq!(
            msg_header.correction_field,
            TimeInterval(I48F16::from_bits(900))
        );

        let mut action = state.handle_event_receive(
            Message {
                header: Header {
                    sequence_id: 879,
                    source_port_identity: PortIdentity {
                        port_number: 12,
                        ..Default::default()
                    },
                    correction_field: TimeInterval(I48F16::from_bits(200)),
                    ..Default::default()
                },
                body: MessageBody::DelayReq(DelayReqMessage {
                    origin_timestamp: Time::from_micros(0).into(),
                }),
                suffix: TlvSet::default(),
            },
            Time::from_fixed_nanos(U96F32::from_bits((220000 << 32) + (300 << 16))),
            Interval::from_log_2(5),
            PortIdentity::default(),
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = action.next() else {
            panic!("Unexpected resulting action");
        };
        assert!(action.next().is_none());

        let msg = Message::deserialize(data).unwrap();
        let msg_header = msg.header;

        let msg = match msg.body {
            MessageBody::DelayResp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(
            msg.requesting_port_identity,
            PortIdentity {
                port_number: 12,
                ..Default::default()
            }
        );
        assert_eq!(msg_header.sequence_id, 879);
        assert_eq!(msg.receive_timestamp, Time::from_micros(220).into());
        assert_eq!(msg_header.log_message_interval, 5);
        assert_eq!(
            msg_header.correction_field,
            TimeInterval(I48F16::from_bits(500))
        );
    }

    #[test]
    fn test_announce() {
        let mut buffer = [0u8; MAX_DATA_LEN];

        let default_ds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });
        let mut parent_ds = ParentDS::new(default_ds);
        parent_ds.grandmaster_priority_1 = 15;
        let current_ds = CurrentDS::default();
        let time_properties_ds = TimePropertiesDS::default();
        let global = PtpInstanceState {
            default_ds,
            current_ds,
            parent_ds,
            time_properties_ds,
        };

        let config = PortConfig {
            delay_mechanism: crate::DelayMechanism::E2E {
                interval: Interval::TWO_SECONDS,
            },
            announce_interval: Interval::TWO_SECONDS,
            announce_receipt_timeout: 2,
            sync_interval: Interval::ONE_SECOND,
            master_only: false,
            delay_asymmetry: Duration::ZERO,
        };
        let mut state = MasterState::new();

        let mut actions =
            state.send_announce(&global, &config, PortIdentity::default(), &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetAnnounceTimer { .. })
        ));
        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let msg = Message::deserialize(data).unwrap();
        let msg_header = msg.header;

        let msg = match msg.body {
            MessageBody::Announce(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(msg.grandmaster_priority_1, 15);

        let mut actions =
            state.send_announce(&global, &config, PortIdentity::default(), &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetAnnounceTimer { .. })
        ));
        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());

        let msg2 = Message::deserialize(data).unwrap();
        let msg2_header = msg2.header;

        let msg2 = match msg2.body {
            MessageBody::Announce(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(msg2.grandmaster_priority_1, 15);
        assert_ne!(msg2_header.sequence_id, msg_header.sequence_id);
    }

    #[test]
    fn test_sync() {
        let mut buffer = [0u8; MAX_DATA_LEN];
        let config = PortConfig {
            delay_mechanism: crate::DelayMechanism::E2E {
                interval: Interval::TWO_SECONDS,
            },
            announce_interval: Interval::TWO_SECONDS,
            announce_receipt_timeout: 2,
            sync_interval: Interval::ONE_SECOND,
            master_only: false,
            delay_asymmetry: crate::Duration::ZERO,
        };

        let mut state = MasterState::new();
        let defaultds = DefaultDS::new(InstanceConfig {
            clock_identity: ClockIdentity::default(),
            priority_1: 15,
            priority_2: 128,
            domain_number: 0,
            slave_only: false,
            sdo_id: SdoId::default(),
        });

        let mut actions =
            state.send_sync(&config, PortIdentity::default(), &defaultds, &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetSyncTimer { .. })
        ));
        let Some(PortAction::SendTimeCritical { context, data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let sync = Message::deserialize(data).unwrap();
        let sync_header = sync.header;

        let _sync = match sync.body {
            MessageBody::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let mut actions = state.handle_timestamp(
            context,
            Time::from_fixed_nanos(U96F32::from_bits((601300 << 32) + (230 << 16))),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let follow = Message::deserialize(data).unwrap();
        let follow_header = follow.header;

        let follow = match follow.body {
            MessageBody::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(sync_header.sequence_id, follow_header.sequence_id);
        assert_eq!(
            sync_header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow.precise_origin_timestamp,
            Time::from_fixed_nanos(601300).into()
        );
        assert_eq!(
            follow_header.correction_field,
            TimeInterval(I48F16::from_bits(230))
        );

        let mut actions =
            state.send_sync(&config, PortIdentity::default(), &defaultds, &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetSyncTimer { .. })
        ));
        let Some(PortAction::SendTimeCritical { context, data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let sync2 = Message::deserialize(data).unwrap();
        let sync2_header = sync2.header;

        let _sync2 = match sync2.body {
            MessageBody::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let mut actions = state.handle_timestamp(
            context,
            Time::from_fixed_nanos(U96F32::from_bits((1000601300 << 32) + (543 << 16))),
            PortIdentity::default(),
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());

        let follow2 = Message::deserialize(data).unwrap();
        let follow2_header = follow2.header;

        let follow2 = match follow2.body {
            MessageBody::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_ne!(sync_header.sequence_id, sync2_header.sequence_id);
        assert_eq!(sync2_header.sequence_id, follow2_header.sequence_id);
        assert_eq!(
            sync2_header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow2.precise_origin_timestamp,
            Time::from_fixed_nanos(1000601300).into()
        );
        assert_eq!(
            follow2_header.correction_field,
            TimeInterval(I48F16::from_bits(543))
        );
    }
}
