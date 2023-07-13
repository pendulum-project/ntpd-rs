use core::{cell::RefCell, fmt::Debug};

use crate::{
    clock::Clock,
    datastructures::{
        common::{PortIdentity, WireTimestamp},
        datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS},
        messages::{DelayReqMessage, Message, MessageBuilder},
    },
    network::NetworkPort,
    port::{
        error::{PortError, Result},
        sequence_id::SequenceIdGenerator,
        PortAction, PortActionIterator, TimestampContext, TimestampContextInner,
    },
    time::Time,
    PortConfig,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MasterState {
    pub(in crate::port) announce_seq_ids: SequenceIdGenerator,
    pub(in crate::port) sync_seq_ids: SequenceIdGenerator,
}

impl MasterState {
    pub fn new() -> Self {
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
        let packet_length = match MessageBuilder::new()
            .sdo_id(default_ds.sdo_id)
            .domain_number(default_ds.domain_number)
            .sequence_id(id)
            .source_port_identity(port_identity)
            .correction_field(timestamp.subnano())
            .follow_up_message(timestamp.into())
            .serialize(buffer)
        {
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
        local_clock: &RefCell<impl Clock>,
        config: &PortConfig,
        default_ds: &DefaultDS,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::trace!("sending sync message");

        let current_time = match local_clock.try_borrow().map(|borrow| borrow.now()) {
            Ok(time) => time,
            Err(error) => {
                log::error!("Statime bug: Clock busy {:?}", error);
                return actions![];
            }
        };

        let seq_id = self.sync_seq_ids.generate();
        let packet_length = match MessageBuilder::new()
            .sdo_id(default_ds.sdo_id)
            .domain_number(default_ds.domain_number)
            .two_step_flag(true)
            .sequence_id(seq_id)
            .source_port_identity(config.port_identity)
            .sync_message(current_time.into())
            .serialize(buffer)
        {
            Ok(message) => message,
            Err(error) => {
                log::error!("Statime bug: Could not serialize sync: {:?}", error);
                return actions![];
            }
        };

        actions![
            PortAction::ResetSyncTimer {
                duration: core::time::Duration::from_secs_f64(
                    2f64.powi(config.log_sync_interval as i32),
                ),
            },
            PortAction::SendTimeCritical {
                context: TimestampContext {
                    inner: TimestampContextInner::Sync { id: seq_id },
                },
                data: &buffer[..packet_length],
            }
        ]
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_announce<P: NetworkPort>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        default_ds: &DefaultDS,
        time_properties: &TimePropertiesDS,
        parent_ds: &ParentDS,
        current_ds: &CurrentDS,
        network_port: &mut P,
        port_identity: PortIdentity,
    ) -> Result<()> {
        log::trace!("sending announce message");

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        let announce_message = MessageBuilder::new()
            .sdo_id(default_ds.sdo_id)
            .domain_number(default_ds.domain_number)
            .leap59(time_properties.leap59())
            .leap61(time_properties.leap61())
            .current_utc_offset_valid(time_properties.current_utc_offset_valid)
            .ptp_timescale(time_properties.ptp_timescale)
            .time_tracable(time_properties.time_traceable)
            .frequency_tracable(time_properties.frequency_traceable)
            .sequence_id(self.announce_seq_ids.generate())
            .source_port_identity(port_identity)
            .announce_message(
                current_time.into(), // origin_timestamp: Timestamp,
                time_properties.current_utc_offset,
                parent_ds.grandmaster_priority_1,
                parent_ds.grandmaster_clock_quality,
                parent_ds.grandmaster_priority_2,
                parent_ds.grandmaster_identity,
                current_ds.steps_removed,
                time_properties.time_source,
            )
            .serialize_vec()?;

        if let Err(error) = network_port.send(&announce_message).await {
            log::error!("failed to send announce message: {:?}", error);
        }

        Ok(())
    }

    pub(crate) fn handle_event_receive<'a>(
        &mut self,
        message: Message,
        timestamp: Time,
        min_delay_req_interval: i8,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        if message.header().source_port_identity() == port_identity {
            return actions![];
        }

        match message {
            Message::DelayReq(message) => self.handle_delay_req(
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
        message: DelayReqMessage,
        timestamp: Time,
        min_delay_req_interval: i8,
        port_identity: PortIdentity,
        buffer: &'a mut [u8],
    ) -> PortActionIterator<'a> {
        log::debug!("Received DelayReq");
        let delay_resp_message = MessageBuilder::new()
            .copy_header(Message::DelayReq(message))
            .two_step_flag(false)
            .source_port_identity(port_identity)
            .add_to_correction(timestamp.subnano())
            .log_message_interval(min_delay_req_interval)
            .delay_resp_message(
                WireTimestamp::from(timestamp),
                message.header().source_port_identity(),
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
    use std::vec::Vec;

    use fixed::types::{I48F16, U96F32};

    use super::*;
    use crate::{
        datastructures::{
            common::{ClockIdentity, TimeInterval},
            messages::{Header, SdoId},
        },
        MAX_DATA_LEN,
    };

    #[derive(Debug, Default)]
    struct TestNetworkPort {
        normal: Vec<Vec<u8>>,
        time: Vec<Vec<u8>>,

        current_time: Time,
    }

    impl NetworkPort for TestNetworkPort {
        type Error = std::convert::Infallible;

        async fn send(&mut self, data: &[u8]) -> core::result::Result<(), Self::Error> {
            self.normal.push(Vec::from(data));
            Ok(())
        }

        async fn send_time_critical(
            &mut self,
            data: &[u8],
        ) -> core::result::Result<Option<Time>, Self::Error> {
            self.time.push(Vec::from(data));
            Ok(Some(self.current_time))
        }

        async fn recv(
            &mut self,
        ) -> core::result::Result<crate::network::NetworkPacket, Self::Error> {
            panic!("Recv shouldn't be called by state");
        }
    }

    struct TestClock {
        current_time: Time,
    }

    impl Clock for TestClock {
        type Error = std::convert::Infallible;

        fn now(&self) -> Time {
            self.current_time
        }

        fn quality(&self) -> crate::datastructures::common::ClockQuality {
            panic!("Shouldn't be called");
        }

        fn adjust(
            &mut self,
            _time_offset: crate::time::Duration,
            _frequency_multiplier: f64,
            _time_properties_ds: &crate::datastructures::datasets::TimePropertiesDS,
        ) -> core::result::Result<(), Self::Error> {
            panic!("Shouldn't be called");
        }
    }

    #[test]
    fn test_delay_response() {
        let mut state = MasterState::new();

        let mut buffer = [0u8; MAX_DATA_LEN];

        let mut action = state.handle_event_receive(
            Message::DelayReq(DelayReqMessage {
                header: Header {
                    sequence_id: 5123,
                    source_port_identity: PortIdentity {
                        port_number: 83,
                        ..Default::default()
                    },
                    correction_field: TimeInterval(I48F16::from_bits(400)),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_fixed_nanos(U96F32::from_bits((200000 << 32) + (500 << 16))),
            2,
            PortIdentity::default(),
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = action.next() else {
            panic!("Unexpected resulting action");
        };
        assert!(action.next().is_none());
        drop(action);

        let msg = match Message::deserialize(data).unwrap() {
            Message::DelayResp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(
            msg.requesting_port_identity,
            PortIdentity {
                port_number: 83,
                ..Default::default()
            }
        );
        assert_eq!(msg.header.sequence_id, 5123);
        assert_eq!(msg.receive_timestamp, Time::from_micros(200).into());
        assert_eq!(msg.header.log_message_interval, 2);
        assert_eq!(
            msg.header.correction_field,
            TimeInterval(I48F16::from_bits(900))
        );

        let mut action = state.handle_event_receive(
            Message::DelayReq(DelayReqMessage {
                header: Header {
                    sequence_id: 879,
                    source_port_identity: PortIdentity {
                        port_number: 12,
                        ..Default::default()
                    },
                    correction_field: TimeInterval(I48F16::from_bits(200)),
                    ..Default::default()
                },
                origin_timestamp: Time::from_micros(0).into(),
            }),
            Time::from_fixed_nanos(U96F32::from_bits((220000 << 32) + (300 << 16))),
            5,
            PortIdentity::default(),
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = action.next() else {
            panic!("Unexpected resulting action");
        };
        assert!(action.next().is_none());

        let msg = match Message::deserialize(data).unwrap() {
            Message::DelayResp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(
            msg.requesting_port_identity,
            PortIdentity {
                port_number: 12,
                ..Default::default()
            }
        );
        assert_eq!(msg.header.sequence_id, 879);
        assert_eq!(msg.receive_timestamp, Time::from_micros(220).into());
        assert_eq!(msg.header.log_message_interval, 5);
        assert_eq!(
            msg.header.correction_field,
            TimeInterval(I48F16::from_bits(500))
        );
    }

    #[test]
    fn test_announce() {
        let mut port = TestNetworkPort::default();
        let clock = RefCell::new(TestClock {
            current_time: Time::from_micros(600),
        });
        let id = SdoId::default();

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, id);
        let mut parent_ds = ParentDS::new(defaultds);
        parent_ds.grandmaster_priority_1 = 15;
        let current_ds = CurrentDS::default();
        let time_properties = TimePropertiesDS::default();

        let mut state = MasterState::new();

        embassy_futures::block_on(state.send_announce(
            &clock,
            &defaultds,
            &time_properties,
            &parent_ds,
            &current_ds,
            &mut port,
            PortIdentity::default(),
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 0);

        let msg = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
            Message::Announce(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(msg.grandmaster_priority_1, 15);

        embassy_futures::block_on(state.send_announce(
            &clock,
            &defaultds,
            &time_properties,
            &parent_ds,
            &current_ds,
            &mut port,
            PortIdentity::default(),
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 0);

        let msg2 = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
            Message::Announce(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(msg2.grandmaster_priority_1, 15);
        assert_ne!(msg2.header.sequence_id, msg.header.sequence_id);
    }

    #[test]
    fn test_sync() {
        let mut buffer = [0u8; MAX_DATA_LEN];
        let config = PortConfig {
            port_identity: PortIdentity::default(),
            delay_mechanism: crate::DelayMechanism::E2E { log_interval: 1 },
            log_announce_interval: 1,
            announce_receipt_timeout: 2,
            log_sync_interval: 0,
            master_only: false,
            delay_asymmetry: crate::Duration::ZERO,
        };

        let clock = RefCell::new(TestClock {
            current_time: Time::from_fixed_nanos(U96F32::from_bits((600000 << 32) + (248 << 16))),
        });

        let mut state = MasterState::new();
        let defaultds = DefaultDS::new_ordinary_clock(
            ClockIdentity::default(),
            15,
            128,
            0,
            false,
            SdoId::default(),
        );

        let mut actions = state.send_sync(&clock, &config, &defaultds, &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetSyncTimer { .. })
        ));
        let Some(PortAction::SendTimeCritical { context, data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let sync = match Message::deserialize(&data).unwrap() {
            Message::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let mut actions = state.handle_timestamp(
            context,
            Time::from_fixed_nanos(U96F32::from_bits((601300 << 32) + (230 << 16))),
            config.port_identity,
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let follow = match Message::deserialize(&data).unwrap() {
            Message::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(sync.header.sequence_id, follow.header.sequence_id);
        assert_eq!(sync.origin_timestamp, Time::from_micros(600).into());
        assert_eq!(
            sync.header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow.precise_origin_timestamp,
            Time::from_fixed_nanos(601300).into()
        );
        assert_eq!(
            follow.header.correction_field,
            TimeInterval(I48F16::from_bits(230))
        );

        clock.borrow_mut().current_time =
            Time::from_fixed_nanos(U96F32::from_bits((1000600000 << 32) + (192 << 16)));
        let mut actions = state.send_sync(&clock, &config, &defaultds, &mut buffer);

        assert!(matches!(
            actions.next(),
            Some(PortAction::ResetSyncTimer { .. })
        ));
        let Some(PortAction::SendTimeCritical { context, data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());
        drop(actions);

        let sync2 = match Message::deserialize(&data).unwrap() {
            Message::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let mut actions = state.handle_timestamp(
            context,
            Time::from_fixed_nanos(U96F32::from_bits((1000601300 << 32) + (543 << 16))),
            config.port_identity,
            &defaultds,
            &mut buffer,
        );

        let Some(PortAction::SendGeneral { data }) = actions.next() else {
            panic!("Unexpected action");
        };
        assert!(actions.next().is_none());

        let follow2 = match Message::deserialize(&data).unwrap() {
            Message::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_ne!(sync.header.sequence_id, sync2.header.sequence_id);
        assert_eq!(sync2.header.sequence_id, follow2.header.sequence_id);
        assert_eq!(sync2.origin_timestamp, Time::from_micros(1000600).into());
        assert_eq!(
            sync2.header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow2.precise_origin_timestamp,
            Time::from_fixed_nanos(1000601300).into()
        );
        assert_eq!(
            follow2.header.correction_field,
            TimeInterval(I48F16::from_bits(543))
        );
    }
}
