use core::cell::RefCell;
use std::fmt::Debug;
use thiserror::Error;

use crate::clock::Clock;
use crate::datastructures::common::{PortIdentity, Timestamp};
use crate::datastructures::datasets::{CurrentDS, DefaultDS, ParentDS, TimePropertiesDS};
use crate::datastructures::messages::{DelayReqMessage, Message, MessageBuilder};
use crate::network::NetworkPort;
use crate::port::error::{PortError, Result};
use crate::port::sequence_id::SequenceIdGenerator;
use crate::time::Instant;

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

    pub(crate) async fn send_sync<P: NetworkPort>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        network_port: &mut P,
        port_identity: PortIdentity,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        log::trace!("sending sync message");

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        let seq_id = self.sync_seq_ids.generate();
        let sync_message = MessageBuilder::new()
            .sdo_id(default_ds.sdo_id)
            .domain_number(default_ds.domain_number)
            .two_step_flag(true)
            .sequence_id(seq_id)
            .source_port_identity(port_identity)
            .sync_message(current_time.into())
            .serialize_vec()?;

        let current_time = match network_port.send_time_critical(&sync_message).await {
            Ok(time) => time,
            Err(error) => {
                log::error!("failed to send sync message: {:?}", error);
                return Err(PortError::Network);
            }
        };

        // TODO: Discuss whether follow up is a config?
        let follow_up_message = MessageBuilder::new()
            .sdo_id(default_ds.sdo_id)
            .domain_number(default_ds.domain_number)
            .sequence_id(seq_id)
            .source_port_identity(port_identity)
            .correction_field(current_time.subnano())
            .follow_up_message(current_time.into())
            .serialize_vec()?;

        if let Err(error) = network_port.send(&follow_up_message).await {
            log::error!("failed to send follow-up message: {:?}", error);
            return Err(PortError::Network);
        }

        Ok(())
    }

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
                current_time.into(), //origin_timestamp: Timestamp,
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

    pub(crate) async fn handle_message<P: NetworkPort>(
        &mut self,
        message: Message,
        current_time: Instant,
        network_port: &mut P,
        log_message_interval: i8,
        port_identity: PortIdentity,
    ) -> Result<()> {
        // Always ignore messages from own port
        if message.header().source_port_identity() != port_identity {
            match message {
                Message::DelayReq(message) => {
                    self.handle_delay_req(
                        message,
                        current_time,
                        network_port,
                        log_message_interval,
                        port_identity,
                    )
                    .await
                }
                _ => Err(MasterError::UnexpectedMessage.into()),
            }
        } else {
            Ok(())
        }
    }

    async fn handle_delay_req<P: NetworkPort>(
        &mut self,
        message: DelayReqMessage,
        current_time: Instant,
        network_port: &mut P,
        log_message_interval: i8,
        port_identity: PortIdentity,
    ) -> Result<(), PortError> {
        log::debug!("Received DelayReq");
        let delay_resp_message = MessageBuilder::new()
            .copy_header(Message::DelayReq(message))
            .two_step_flag(false)
            .source_port_identity(port_identity)
            .add_to_correction(current_time.subnano())
            .log_message_interval(log_message_interval)
            .delay_resp_message(
                Timestamp::from(current_time),
                message.header().source_port_identity(),
            );

        let delay_resp_encode = delay_resp_message.serialize_vec()?;

        network_port
            .send(&delay_resp_encode)
            .await
            .map_err(|_| PortError::Network)?;

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum MasterError {
    #[error("received a message that a port in the master state can never process")]
    UnexpectedMessage,
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use fixed::types::{I48F16, U96F32};

    use crate::datastructures::{
        common::{ClockIdentity, TimeInterval},
        messages::{Header, SdoId},
    };

    use super::*;

    #[derive(Debug, Default)]
    struct TestNetworkPort {
        normal: Vec<Vec<u8>>,
        time: Vec<Vec<u8>>,

        current_time: Instant,
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
        ) -> core::result::Result<Instant, Self::Error> {
            self.time.push(Vec::from(data));
            Ok(self.current_time)
        }

        async fn recv(
            &mut self,
        ) -> core::result::Result<crate::network::NetworkPacket, Self::Error> {
            panic!("Recv shouldn't be called by state");
        }
    }

    struct TestClock {
        current_time: Instant,
    }

    impl Clock for TestClock {
        type Error = std::convert::Infallible;

        fn now(&self) -> Instant {
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
        let mut port = TestNetworkPort::default();

        let mut state = MasterState::new();

        embassy_futures::block_on(state.handle_message(
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
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_fixed_nanos(U96F32::from_bits((200000 << 32) + (500 << 16))),
            &mut port,
            2,
            PortIdentity::default(),
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 0);

        let msg = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
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
        assert_eq!(msg.receive_timestamp, Instant::from_micros(200).into());
        assert_eq!(msg.header.log_message_interval, 2);
        assert_eq!(
            msg.header.correction_field,
            TimeInterval(I48F16::from_bits(900))
        );

        embassy_futures::block_on(state.handle_message(
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
                origin_timestamp: Instant::from_micros(0).into(),
            }),
            Instant::from_fixed_nanos(U96F32::from_bits((220000 << 32) + (300 << 16))),
            &mut port,
            5,
            PortIdentity::default(),
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 0);

        let msg = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
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
        assert_eq!(msg.receive_timestamp, Instant::from_micros(220).into());
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
            current_time: Instant::from_micros(600),
        });
        let id = SdoId::default();

        let defaultds =
            DefaultDS::new_ordinary_clock(ClockIdentity::default(), 15, 128, 0, false, id);
        let mut parent_ds = ParentDS::default();
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
        let mut port = TestNetworkPort::default();
        let clock = RefCell::new(TestClock {
            current_time: Instant::from_fixed_nanos(U96F32::from_bits(
                (600000 << 32) + (248 << 16),
            )),
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

        port.current_time =
            Instant::from_fixed_nanos(U96F32::from_bits((601300 << 32) + (230 << 16)));
        embassy_futures::block_on(state.send_sync(
            &clock,
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 1);

        let sync = match Message::deserialize(&port.time.pop().unwrap()).unwrap() {
            Message::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let follow = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
            Message::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_eq!(sync.header.sequence_id, follow.header.sequence_id);
        assert_eq!(sync.origin_timestamp, Instant::from_micros(600).into());
        assert_eq!(
            sync.header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow.precise_origin_timestamp,
            Instant::from_fixed_nanos(601300).into()
        );
        assert_eq!(
            follow.header.correction_field,
            TimeInterval(I48F16::from_bits(230))
        );

        clock.borrow_mut().current_time =
            Instant::from_fixed_nanos(U96F32::from_bits((1000600000 << 32) + (192 << 16)));
        port.current_time =
            Instant::from_fixed_nanos(U96F32::from_bits((1000601300 << 32) + (543 << 16)));
        embassy_futures::block_on(state.send_sync(
            &clock,
            &mut port,
            PortIdentity::default(),
            &defaultds,
        ))
        .unwrap();

        assert_eq!(port.normal.len(), 1);
        assert_eq!(port.time.len(), 1);

        let sync2 = match Message::deserialize(&port.time.pop().unwrap()).unwrap() {
            Message::Sync(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        let follow2 = match Message::deserialize(&port.normal.pop().unwrap()).unwrap() {
            Message::FollowUp(msg) => msg,
            _ => panic!("Unexpected message type"),
        };

        assert_ne!(sync.header.sequence_id, sync2.header.sequence_id);
        assert_eq!(sync2.header.sequence_id, follow2.header.sequence_id);
        assert_eq!(sync2.origin_timestamp, Instant::from_micros(1000600).into());
        assert_eq!(
            sync2.header.correction_field,
            TimeInterval(I48F16::from_bits(0))
        );
        assert_eq!(
            follow2.precise_origin_timestamp,
            Instant::from_fixed_nanos(1000601300).into()
        );
        assert_eq!(
            follow2.header.correction_field,
            TimeInterval(I48F16::from_bits(543))
        );
    }
}
