use core::cell::RefCell;
use std::convert::Infallible;
use std::ops::DerefMut;

use embassy_futures::select;
use embassy_futures::select::{Either, Either4};
use futures::pin_mut;

pub use measurement::Measurement;

use crate::bmc::bmca::{Bmca, RecommendedState};
use crate::clock::{Clock, Timer};
use crate::datastructures::common::{PortIdentity, TimeSource, Timestamp};
use crate::datastructures::datasets::{DefaultDS, PortDS, TimePropertiesDS};
use crate::datastructures::messages::{AnnounceMessage, Message, MessageBuilder};
use crate::filters::Filter;
use crate::network::{NetworkPort, NetworkRuntime};
use crate::port::state::{MasterState, PortState, SlaveState};
use crate::time::Instant;

mod error;
mod measurement;
mod sequence_id;
pub mod state;
#[cfg(test)]
mod test;

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
}

impl<P: NetworkPort> Port<P> {
    pub async fn run_port<C: Clock, F: Filter, const N: usize>(
        &mut self,
        timer: &impl Timer,
        clock: &RefCell<C>,
        filter: &RefCell<F>,
        default_ds: &DefaultDS,
        time_properties_ds: &RefCell<TimePropertiesDS>,
        announce_messages: &RefCell<[Option<(AnnounceMessage, Timestamp, PortIdentity)>; N]>,
    ) -> Infallible {
        let bmca_timeout = timer.after(self.port_ds.announce_interval());
        pin_mut!(bmca_timeout);
        let announce_receipt_timeout = timer.after(self.port_ds.announce_receipt_interval());
        pin_mut!(announce_receipt_timeout);
        let sync_timeout = timer.after(self.port_ds.sync_interval());
        pin_mut!(sync_timeout);
        let announce_timeout = timer.after(self.port_ds.announce_interval());
        pin_mut!(announce_timeout);

        loop {
            let timeouts = select::select4(
                &mut bmca_timeout,
                &mut announce_receipt_timeout,
                &mut sync_timeout,
                &mut announce_timeout,
            );
            let packet = self.network_port.recv();
            match select::select(timeouts, packet).await {
                Either::First(timeout) => match timeout {
                    Either4::First(_) => {
                        log::trace!("running bmca");
                        match clock.try_borrow() {
                            Ok(clock) => {
                                self.run_bmca(
                                    clock.now(),
                                    announce_messages,
                                    default_ds,
                                    time_properties_ds,
                                );
                            }
                            Err(_) => log::error!("failed to get current time"),
                        }
                        bmca_timeout.set(timer.after(self.port_ds.announce_interval()));
                    }
                    Either4::Second(_) => {
                        match self.port_ds.port_state {
                            PortState::Master(_) => {}
                            _ => {
                                log::info!(
                                    "New state for port: {} -> Master",
                                    self.port_ds.port_state
                                );
                                self.port_ds.port_state = PortState::Master(MasterState::new());
                            }
                        }
                        announce_timeout.set(timer.after(self.port_ds.announce_receipt_interval()));
                    }
                    Either4::Third(_) => {
                        log::trace!("sending sync message");
                        match clock.try_borrow() {
                            Ok(clock) => {
                                if let PortState::Master(master) = &mut self.port_ds.port_state {
                                    let sync_message = MessageBuilder::new()
                                        .sequence_id(master.sync_seq_ids.generate())
                                        .source_port_identity(self.port_ds.port_identity)
                                        .sync_message(Timestamp::from(clock.now()));

                                    let sync_message_encode = sync_message.serialize_vec().unwrap();
                                    self.network_port.send(&sync_message_encode);

                                    // TODO: Is the follow up a config?
                                    let follow_up_message = MessageBuilder::new()
                                        .sequence_id(master.sync_seq_ids.generate())
                                        .source_port_identity(self.port_ds.port_identity)
                                        .follow_up_message(Timestamp::from(clock.now()));

                                    let follow_up_message_encode =
                                        follow_up_message.serialize_vec().unwrap();
                                    self.network_port.send(&follow_up_message_encode);
                                }
                            }
                            Err(_) => log::error!("failed to get current time"),
                        }
                        sync_timeout.set(timer.after(self.port_ds.sync_interval()));
                    }
                    Either4::Fourth(_) => {
                        log::trace!("sending announce message");
                        if let PortState::Master(master) = &mut self.port_ds.port_state {
                            let announce_message = MessageBuilder::new()
                                .sequence_id(master.announce_seq_ids.generate())
                                .source_port_identity(self.port_ds.port_identity)
                                .announce_message(
                                    Timestamp::default(),             //origin_timestamp: Timestamp,
                                    0, // TODO implement current_utc_offset: u16,
                                    default_ds.priority_1, //grandmaster_priority_1: u8,
                                    default_ds.clock_quality, //grandmaster_clock_quality: ClockQuality,
                                    default_ds.priority_2,    //grandmaster_priority_2: u8,
                                    default_ds.clock_identity, //grandmaster_identity: ClockIdentity,
                                    0,                         // TODO implement steps_removed: u16,
                                    TimeSource::from_primitive(0xa0), // TODO implement time_source: TimeSource,
                                );

                            let announce_message_encode = announce_message.serialize_vec().unwrap();
                            self.network_port.send(&announce_message_encode);
                        }
                        announce_timeout.set(timer.after(self.port_ds.announce_interval()));
                    }
                },
                Either::Second(Ok(packet)) => {
                    let message = match Message::deserialize(&packet.data) {
                        Ok(message) => {
                            log::trace!("received message: {:?}", message);
                            message
                        }
                        Err(error) => {
                            log::error!("received invalid message: {:?}", error);
                            continue;
                        }
                    };

                    if message.header().sdo_id() == default_ds.sdo_id
                        && message.header().domain_number() == default_ds.domain_number
                    {
                        match clock.try_borrow_mut() {
                            Ok(mut clock) => {
                                // Only process messages from the same domai
                                if let Message::Announce(announce) = &message {
                                    self.bmca
                                        .register_announce_message(announce, clock.now().into());

                                    announce_receipt_timeout
                                        .set(timer.after(self.port_ds.announce_receipt_interval()));
                                } else {
                                    self.port_ds
                                        .port_state
                                        .handle_message(
                                            message,
                                            clock.now(),
                                            &mut self.network_port,
                                            self.port_ds.port_identity,
                                        )
                                        .await;

                                    // If the received packet allowed the (slave) state to calculate its
                                    // offset from the master, update the local clock
                                    if let PortState::Slave(state) = &mut self.port_ds.port_state {
                                        if let Ok(measurement) = state.extract_measurement() {
                                            match filter.try_borrow_mut() {
                                                Ok(mut filter) => {
                                                    let (offset, freq_corr) =
                                                        filter.absorb(measurement);
                                                    match time_properties_ds.try_borrow() {
                                                        Ok(time_properties_ds) => {
                                                            // TODO: Currently returns bool instead of ()
                                                            clock
                                                                .adjust(
                                                                    offset,
                                                                    freq_corr,
                                                                    &time_properties_ds,
                                                                )
                                                                .expect(
                                                                    "Unexpected error adjusting clock",
                                                                );
                                                        }
                                                        Err(_) => {
                                                            log::error!(
                                                                "could not retrieve time properties"
                                                            )
                                                        }
                                                    }
                                                }
                                                Err(_) => log::error!("could not retrieve filter"),
                                            }
                                        }
                                    }
                                }
                            }
                            _ => log::warn!("multiple ports are in slave state (which is wrong)"),
                        }
                    }
                }

                Either::Second(Err(error)) => panic!("{:?}", error),
            }
        }
    }

    fn run_bmca<const N: usize>(
        &mut self,
        current_time: Instant,
        announce_messages: &RefCell<[Option<(AnnounceMessage, Timestamp, PortIdentity)>; N]>,
        default_ds: &DefaultDS,
        time_properties_ds: &RefCell<TimePropertiesDS>,
    ) {
        let erbest = self.take_best_port_announce_message(current_time);

        let ebest = match announce_messages.try_borrow_mut() {
            Ok(mut announce_messages) => {
                // TODO: lelijk >:(
                let index = (self.port_ds.port_identity.port_number - 1) as usize;
                announce_messages[index] = erbest;
                Bmca::find_best_announce_message(announce_messages.into_iter().flatten())
            }
            Err(_) => {
                log::error!("could not access announce messages for BMCA");
                return;
            }
        };

        // TODO: Cleanup
        let erbest = erbest
            .as_ref()
            .map(|(message, _, identity)| (message, identity));
        let ebest = ebest
            .as_ref()
            .map(|(message, _, identity)| (message, identity));

        // Run the state decision
        match time_properties_ds.try_borrow_mut() {
            Ok(mut time_properties_ds) => {
                self.perform_state_decision(
                    ebest,
                    erbest,
                    default_ds,
                    time_properties_ds.deref_mut(),
                );
            }
            Err(_) => log::error!("could not change time properties"),
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
        let recommended_state = Bmca::calculate_recommended_state(
            &default_ds,
            best_global_announce_message,
            best_port_announce_message,
            &self.port_ds.port_state,
        );

        if let Some(recommended_state) = recommended_state {
            self.handle_recommended_state(&recommended_state);

            if let RecommendedState::S1(announce_message) = &recommended_state {
                // Update time properties
                *time_properties_ds = announce_message.time_properties();
            }
        }
    }

    fn handle_recommended_state(&mut self, recommended_state: &RecommendedState) {
        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => match &mut self.port_ds.port_state {
                PortState::Listening => {
                    self.port_ds.port_state = PortState::Slave(SlaveState::new(
                        announce_message.header().source_port_identity(),
                    ));

                    log::info!(
                        "New state for port: Listening -> Slave. Remote master: {:?}",
                        announce_message
                            .header()
                            .source_port_identity()
                            .clock_identity
                    );
                }

                PortState::Slave(slave_state) => {
                    // TODO: Changing the master should recalibrate the slave
                    slave_state.remote_master = announce_message.header().source_port_identity();
                }

                // Transition MASTER to SLAVE
                PortState::Master(_) => {
                    self.port_ds.port_state = PortState::Slave(SlaveState::new(
                        announce_message.header().source_port_identity(),
                    ));

                    log::info!("New state for port: Master -> Slave");
                }
                PortState::Initializing => unimplemented!(),
                PortState::Faulty => unimplemented!(),
                PortState::Disabled => unimplemented!(),
                PortState::PreMaster => unimplemented!(),
                PortState::Passive => unimplemented!(),
                PortState::Uncalibrated => unimplemented!(),
            },

            // Recommended state is master
            RecommendedState::M2(_) => match &self.port_ds.port_state {
                // Stay master
                PortState::Master(_) => (),
                // Otherwise become master
                _ => {
                    self.port_ds.port_state = PortState::Master(MasterState::new());
                }
            },
            // All other cases
            _ => match &mut self.port_ds.port_state {
                PortState::Listening => {
                    // Ignore
                }
                _ => {
                    self.port_ds.port_state = PortState::Listening;
                    log::info!("New state for port: Listening");
                }
            },
        }
    }
}
