use core::cell::RefCell;
use core::convert::Infallible;
use std::future::Future;
use std::pin::Pin;

use embassy_futures::select;
use embassy_futures::select::{Either, Either4};
use futures::{pin_mut, StreamExt};

pub use error::{PortError, Result};
pub use measurement::Measurement;
use state::{MasterState, PortState};
pub use ticker::Ticker;

use crate::bmc::bmca::{BestAnnounceMessage, Bmca, RecommendedState};
use crate::clock::{Clock, Timer};
use crate::datastructures::common::{PortIdentity, TimeSource};
use crate::datastructures::datasets::{DefaultDS, PortDS, TimePropertiesDS};
use crate::datastructures::messages::{Message, MessageBuilder};
use crate::filters::Filter;
use crate::network::{NetworkPacket, NetworkPort, NetworkRuntime};
use crate::time::Duration;

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
    pub async fn run_port<const N: usize>(
        &mut self,
        timer: &impl Timer,
        local_clock: &RefCell<impl Clock>,
        filter: &RefCell<impl Filter>,
        announce_messages: &RefCell<[Option<BestAnnounceMessage>; N]>,
        default_ds: &DefaultDS,
        time_properties_ds: &RefCell<TimePropertiesDS>,
    ) -> Infallible {
        let bmca_timeout = Ticker::new(
            |interval| timer.after(interval),
            self.port_ds.announce_interval(),
        );
        pin_mut!(bmca_timeout);
        let announce_receipt_timeout = Ticker::new(
            |interval| timer.after(interval),
            self.port_ds.announce_receipt_interval(),
        );
        pin_mut!(announce_receipt_timeout);
        let sync_timeout = Ticker::new(
            |interval| timer.after(interval),
            self.port_ds.sync_interval(),
        );
        pin_mut!(sync_timeout);
        let announce_timeout = Ticker::new(
            |interval| timer.after(interval),
            self.port_ds.announce_interval(),
        );
        pin_mut!(announce_timeout);

        loop {
            let timeouts = select::select4(
                bmca_timeout.next(),
                announce_receipt_timeout.next(),
                sync_timeout.next(),
                announce_timeout.next(),
            );
            let packet = self.network_port.recv();
            match select::select(timeouts, packet).await {
                Either::First(timeout) => match timeout {
                    Either4::First(_) => {
                        // Run best master clock algorithm
                        if let Err(error) = self.run_bmca(
                            local_clock,
                            announce_messages,
                            &mut announce_receipt_timeout,
                            default_ds,
                            time_properties_ds,
                        ) {
                            log::error!("{:?}", error);
                        }
                    }
                    Either4::Second(_) => {
                        // No announces received for a long time, become master
                        match self.port_ds.port_state {
                            PortState::Master(_) => (),
                            _ => self
                                .port_ds
                                .set_forced_port_state(PortState::Master(MasterState::new())),
                        }
                    }
                    Either4::Third(_) => {
                        // Send sync message
                        if let Err(error) = self.send_sync(local_clock).await {
                            log::error!("{:?}", error);
                        }
                    }
                    Either4::Fourth(_) => {
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
                            &mut announce_receipt_timeout,
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

    fn run_bmca<T: Future, const N: usize>(
        &mut self,
        local_clock: &RefCell<impl Clock>,
        announce_messages: &RefCell<[Option<BestAnnounceMessage>; N]>,
        announce_receipt_timeout: &mut Pin<&mut Ticker<T, impl FnMut(Duration) -> T>>,
        default_ds: &DefaultDS,
        time_properties_ds: &RefCell<TimePropertiesDS>,
    ) -> Result<()> {
        log::trace!("running bmca");

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        let erbest = self
            .bmca
            .take_best_port_announce_message(current_time.into());
        let ebest = match announce_messages.try_borrow_mut() {
            Ok(mut announce_messages) => {
                // Uses assertion in PtpInstance constructor
                let index = (self.port_ds.port_identity.port_number - 1) as usize;
                announce_messages[index] = erbest;
                Bmca::find_best_announce_message(announce_messages.into_iter().flatten())
            }
            Err(_) => {
                log::error!("could not access announce messages for BMCA");
                erbest
            }
        };

        let recommended_state =
            Bmca::calculate_recommended_state(default_ds, ebest, erbest, &self.port_ds.port_state);

        if let Some(recommended_state) = recommended_state {
            self.port_ds
                .set_recommended_port_state(&recommended_state, announce_receipt_timeout);

            // TODO: Discuss if we should change the clock's own time properties, or keep the master's time properties separately
            if let RecommendedState::S1(announce_message) = &recommended_state {
                // Update time properties
                let mut time_properties_ds = time_properties_ds
                    .try_borrow_mut()
                    .map_err(|_| PortError::TimePropertiesBusy)?;
                *time_properties_ds = announce_message.time_properties();
            }
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

            let sync_message = MessageBuilder::new()
                .sequence_id(master.sync_seq_ids.generate())
                .source_port_identity(self.port_ds.port_identity)
                .sync_message(current_time.into())
                .serialize_vec()?;

            if let Err(error) = self.network_port.send(&sync_message).await {
                log::error!("failed to send sync message: {:?}", error);
            }

            let current_time = local_clock
                .try_borrow()
                .map(|borrow| borrow.now())
                .map_err(|_| PortError::ClockBusy)?;

            // TODO: Discuss whether follow up is a config?
            let follow_up_message = MessageBuilder::new()
                .sequence_id(master.sync_seq_ids.generate())
                .source_port_identity(self.port_ds.port_identity)
                .follow_up_message(current_time.into())
                .serialize_vec()?;

            if let Err(error) = self.network_port.send(&follow_up_message).await {
                log::error!("failed to send follow-up message: {:?}", error);
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

    async fn handle_packet<T: Future>(
        &mut self,
        packet: NetworkPacket,
        local_clock: &RefCell<impl Clock>,
        filter: &RefCell<impl Filter>,
        announce_receipt_timeout: &mut Pin<&mut Ticker<T, impl FnMut(Duration) -> T>>,
        default_ds: &DefaultDS,
        time_properties_ds: &RefCell<TimePropertiesDS>,
    ) -> Result<()> {
        let message = Message::deserialize(&packet.data)?;

        // Only process messages from the same domain
        if message.header().sdo_id() != default_ds.sdo_id
            || message.header().domain_number() != default_ds.domain_number
        {
            return Ok(());
        }

        let current_time = local_clock
            .try_borrow()
            .map(|borrow| borrow.now())
            .map_err(|_| PortError::ClockBusy)?;

        if let Message::Announce(announce) = &message {
            self.bmca
                .register_announce_message(announce, current_time.into());
            announce_receipt_timeout.reset();
        } else {
            self.port_ds
                .port_state
                .handle_message(
                    message,
                    current_time,
                    &mut self.network_port,
                    self.port_ds.port_identity,
                )
                .await?;

            // If the received message allowed the (slave) state to calculate its offset from the
            // master, update the local clock
            if let PortState::Slave(slave) = &mut self.port_ds.port_state {
                if let Some(measurement) = slave.extract_measurement() {
                    let (offset, freq_corr) = filter
                        .try_borrow_mut()
                        .map(|mut borrow| borrow.absorb(measurement))
                        .map_err(|_| PortError::FilterBusy)?;

                    let mut local_clock = local_clock
                        .try_borrow_mut()
                        .map_err(|_| PortError::ClockBusy)?;
                    let time_properties_ds = time_properties_ds
                        .try_borrow()
                        .map_err(|_| PortError::TimePropertiesBusy)?;

                    if let Err(error) = local_clock.adjust(offset, freq_corr, &time_properties_ds) {
                        log::error!("failed to adjust clock: {:?}", error);
                    }
                }
            }
        }

        Ok(())
    }
}
