use std::fmt::Debug;
use thiserror::Error;

use crate::datastructures::common::{PortIdentity, Timestamp};
use crate::datastructures::messages::{DelayReqMessage, Message, MessageBuilder};
use crate::network::NetworkPort;
use crate::port::error::PortError;
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

    pub async fn handle_message<P: NetworkPort>(
        &mut self,
        message: Message,
        current_time: Instant,
        network_port: &mut P,
        port_identity: PortIdentity,
    ) -> Result<(), PortError> {
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
