use core::cell::RefCell;
use std::fmt::Debug;
use thiserror::Error;

use crate::clock::Clock;
use crate::datastructures::common::{PortIdentity, TimeSource, Timestamp};
use crate::datastructures::datasets::DefaultDS;
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
    ) -> Result<()> {
        log::trace!("sending sync message");

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        let seq_id = self.sync_seq_ids.generate();
        let sync_message = MessageBuilder::new()
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
        network_port: &mut P,
        port_identity: PortIdentity,
    ) -> Result<()> {
        log::trace!("sending announce message");

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        let announce_message = MessageBuilder::new()
            .sequence_id(self.announce_seq_ids.generate())
            .source_port_identity(port_identity)
            .announce_message(
                current_time.into(),              //origin_timestamp: Timestamp,
                0,                                // TODO implement current_utc_offset: u16,
                default_ds.priority_1,            //grandmaster_priority_1: u8,
                default_ds.clock_quality,         //grandmaster_clock_quality: ClockQuality,
                default_ds.priority_2,            //grandmaster_priority_2: u8,
                default_ds.clock_identity,        //grandmaster_identity: ClockIdentity,
                0,                                // TODO implement steps_removed: u16,
                TimeSource::from_primitive(0xa0), // TODO implement time_source: TimeSource,
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
        port_identity: PortIdentity,
    ) -> Result<()> {
        // Always ignore messages from own port
        if message.header().source_port_identity() != port_identity {
            match message {
                Message::DelayReq(message) => {
                    self.handle_delay_req(message, current_time, network_port, port_identity)
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
        port_identity: PortIdentity,
    ) -> Result<(), PortError> {
        log::debug!("Received DelayReq");
        let delay_resp_message = MessageBuilder::new()
            .copy_header(Message::DelayReq(message))
            .two_step_flag(false)
            .source_port_identity(port_identity)
            .add_to_correction(current_time.subnano())
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
