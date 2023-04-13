use core::cell::RefCell;
use std::{future::Future, pin::Pin};

use embassy_futures::{
    select,
    select::{Either, Either3},
};
pub use error::{PortError, Result};
use futures::StreamExt;
pub use measurement::Measurement;
use state::{MasterState, PortState};
pub use ticker::Ticker;

use crate::{
    bmc::bmca::{BestAnnounceMessage, Bmca, RecommendedState},
    clock::Clock,
    datastructures::{
        common::{PortIdentity, TimeSource, Timestamp},
        datasets::{DefaultDS, PortDS, TimePropertiesDS},
        messages::{Message, MessageBuilder},
    },
    filters::Filter,
    network::{NetworkPacket, NetworkPort, NetworkRuntime},
    time::Duration,
};

mod error;
mod measurement;
mod sequence_id;
pub mod state;
#[cfg(test)]
mod tests;
mod ticker;

pub struct Port<P> {
    port_ds: PortDS,
    network_port: P,
    bmca: Bmca,
}

impl<P> Port<P> {
    pub async fn new<NR>(
        port_ds: PortDS,
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

        let bmca = Bmca::new(port_ds.announce_interval().into(), port_ds.port_identity);

        Port {
            port_ds,
            network_port,
            bmca,
        }
    }

    pub fn identity(&self) -> PortIdentity {
        self.port_ds.port_identity
    }
}

impl<P: NetworkPort> Port<P> {
    pub async fn run_port<F: Future>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        filter: &RefCell<impl Filter>,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        sync_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        announce_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        default_ds: &DefaultDS,
        time_properties_ds: &TimePropertiesDS,
    ) -> ! {
        loop {
            let timeouts = select::select3(
                announce_receipt_timeout.next(),
                sync_timeout.next(),
                announce_timeout.next(),
            );
            let packet = self.network_port.recv();
            match select::select(timeouts, packet).await {
                Either::First(timeout) => match timeout {
                    Either3::First(_) => {
                        // No announces received for a long time, become master
                        match self.port_ds.port_state {
                            PortState::Master(_) => (),
                            _ => self
                                .port_ds
                                .set_forced_port_state(PortState::Master(MasterState::new())),
                        }
                    }
                    Either3::Second(_) => {
                        // Send sync message
                        if let Err(error) = self.send_sync(local_clock).await {
                            log::error!("{:?}", error);
                        }
                    }
                    Either3::Third(_) => {
                        // Send announce message
                        if let Err(error) = self.send_announce(local_clock, default_ds).await {
                            log::error!("{:?}", error);
                        }
                    }
                },
                Either::Second(Ok(packet)) => {
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
                Either::Second(Err(error)) => log::error!("failed to parse packet {:?}", error),
            }
        }
    }

    pub fn best_local_announce_message(
        &mut self,
        current_time: Timestamp,
    ) -> Option<BestAnnounceMessage> {
        self.bmca
            .take_best_port_announce_message(current_time.into())
    }

    pub fn set_recommended_state<F: Future>(
        &mut self,
        recommended_state: RecommendedState,
        announce_receipt_timeout: &mut Pin<&mut Ticker<F, impl FnMut(Duration) -> F>>,
        time_properties_ds: &mut TimePropertiesDS,
    ) -> Result<()> {
        self.port_ds
            .set_recommended_port_state(&recommended_state, announce_receipt_timeout);

        // TODO: Discuss if we should change the clock's own time properties, or keep
        // the master's time properties separately
        if let RecommendedState::S1(announce_message) = &recommended_state {
            // Update time properties
            *time_properties_ds = announce_message.time_properties();
        }

        Ok(())
    }

    async fn send_sync(&mut self, local_clock: &RefCell<impl Clock>) -> Result<()> {
        if let PortState::Master(master) = &mut self.port_ds.port_state {
            log::trace!("sending sync message");

            let current_time = local_clock
                .try_borrow()
                .map(|borrow| borrow.now())
                .map_err(|_| PortError::ClockBusy)?;

            let seq_id = master.sync_seq_ids.generate();
            let sync_message = MessageBuilder::new()
                .sequence_id(seq_id)
                .source_port_identity(self.port_ds.port_identity)
                .sync_message(current_time.into())
                .serialize_vec()?;

            let current_time = match self.network_port.send_time_critical(&sync_message).await {
                Ok(time) => time,
                Err(error) => {
                    log::error!("failed to send sync message: {:?}", error);
                    return Err(PortError::Network);
                }
            };

            // TODO: Discuss whether follow up is a config?
            let follow_up_message = MessageBuilder::new()
                .sequence_id(seq_id)
                .source_port_identity(self.port_ds.port_identity)
                .correction_field(current_time.subnano())
                .follow_up_message(current_time.into())
                .serialize_vec()?;

            if let Err(error) = self.network_port.send(&follow_up_message).await {
                log::error!("failed to send follow-up message: {:?}", error);
                return Err(PortError::Network);
            }
        }

        Ok(())
    }

    async fn send_announce(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        if let PortState::Master(master) = &mut self.port_ds.port_state {
            log::trace!("sending announce message");

            let current_time = local_clock
                .try_borrow()
                .map(|borrow| borrow.now())
                .map_err(|_| PortError::ClockBusy)?;

            let announce_message = MessageBuilder::new()
                .sequence_id(master.announce_seq_ids.generate())
                .source_port_identity(self.port_ds.port_identity)
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

            if let Err(error) = self.network_port.send(&announce_message).await {
                log::error!("failed to send announce message: {:?}", error);
            }
        }

        Ok(())
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
            self.bmca
                .register_announce_message(announce, packet.timestamp.into());
            announce_receipt_timeout.reset();
        } else {
            self.port_ds
                .port_state
                .handle_message(
                    message,
                    packet.timestamp.into(),
                    &mut self.network_port,
                    self.port_ds.port_identity,
                )
                .await?;

            // If the received message allowed the (slave) state to calculate its offset
            // from the master, update the local clock
            if let PortState::Slave(slave) = &mut self.port_ds.port_state {
                if let Some(measurement) = slave.extract_measurement() {
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
        }

        Ok(())
    }

    pub fn announce_interval(&self) -> Duration {
        self.port_ds.announce_interval()
    }

    pub fn sync_interval(&self) -> Duration {
        self.port_ds.sync_interval()
    }

    pub fn announce_receipt_interval(&self) -> Duration {
        self.port_ds.announce_receipt_interval()
    }

    pub fn state(&self) -> &PortState {
        &self.port_ds.port_state
    }
}
