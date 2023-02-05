pub use measurement::Measurement;

use crate::bmc::bmca::{Bmca, RecommendedState};
use crate::clock::Watch;
use crate::datastructures::common::{PortIdentity, TimeSource, Timestamp};
use crate::datastructures::datasets::{DefaultDS, PortDS, TimePropertiesDS};
use crate::datastructures::messages::{AnnounceMessage, Message, MessageBuilder};
use crate::network::{NetworkPacket, NetworkPort, NetworkRuntime};
use crate::port::error::{PortError, Result};
use crate::port::state::{MasterState, PortState, SlaveState};
use crate::time::{Duration, Instant};

mod error;
mod measurement;
mod sequence_id;
pub mod state;
#[cfg(test)]
mod test;

pub struct Port<P, W> {
    port_ds: PortDS,

    pub(crate) bmca_watch: W,
    announce_timeout_watch: W,
    announce_watch: W,
    sync_watch: W,

    tc_port: P,
    nc_port: P,

    bmca: Bmca,
}

impl<P, W> Port<P, W> {
    pub fn new<NR>(
        port_ds: PortDS,
        runtime: &mut NR,
        interface: NR::InterfaceDescriptor,
        bmca_watch: W,
        announce_timeout_watch: W,
        announce_watch: W,
        sync_watch: W,
    ) -> Self
    where
        NR: NetworkRuntime<PortType = P>,
    {
        // Ptp needs two ports, 1 time critical one and 1 general port
        let tc_port = runtime
            .open(interface.clone(), true)
            .expect("Could not create time critical port");
        let nc_port = runtime
            .open(interface, false)
            .expect("Could not create non time critical port");

        let bmca = Bmca::new(
            Duration::from_log_interval(port_ds.log_announce_interval).into(),
            port_ds.port_identity,
        );

        Port {
            port_ds,

            bmca_watch,
            announce_timeout_watch,
            announce_watch,
            sync_watch,

            tc_port,
            nc_port,

            bmca,
        }
    }
}

impl<P: NetworkPort, W: Watch> Port<P, W> {
    pub fn handle_alarm(&mut self, id: W::WatchId, current_time: Instant, default_ds: &DefaultDS) {
        // When the announce timout expires, it means there
        // have been no announce messages in a while, so we
        // force a switch to the master state
        if id == self.announce_timeout_watch.id() {
            log::info!("Announce interval timeout");

            self.port_ds.port_state = PortState::Master(MasterState::new());

            log::info!("New state for port: Master");

            // Start sending announce messages
            self.announce_watch.set_alarm(Duration::from_log_interval(
                self.port_ds.log_announce_interval,
            ));

            // Start sending sync messages
            self.sync_watch
                .set_alarm(Duration::from_log_interval(self.port_ds.log_sync_interval));
        }

        // When the announce watch expires, send an announce message and restart
        if id == self.announce_watch.id() {
            self.send_announce_message(default_ds);
            self.announce_watch.set_alarm(Duration::from_log_interval(
                self.port_ds.log_announce_interval,
            ));
        }

        // When the sync watch expires, send a sync message and restart
        if id == self.sync_watch.id() {
            self.send_sync_message(current_time);

            // TODO: Is the follow up a config?
            self.send_follow_up_message(current_time);

            self.sync_watch
                .set_alarm(Duration::from_log_interval(self.port_ds.log_sync_interval));
        }
    }

    /// Send an announce message
    pub fn send_announce_message(&mut self, default_ds: &DefaultDS) -> Result<()> {
        match &mut self.port_ds.port_state {
            PortState::Master(master) => {
                let announce_message = MessageBuilder::new()
                    .sequence_id(master.announce_seq_ids.generate())
                    .source_port_identity(self.port_ds.port_identity)
                    .announce_message(
                        Timestamp::default(),             //origin_timestamp: Timestamp,
                        0,                                // TODO implement current_utc_offset: u16,
                        default_ds.priority_1,            //grandmaster_priority_1: u8,
                        default_ds.clock_quality,         //grandmaster_clock_quality: ClockQuality,
                        default_ds.priority_2,            //grandmaster_priority_2: u8,
                        default_ds.clock_identity,        //grandmaster_identity: ClockIdentity,
                        0,                                // TODO implement steps_removed: u16,
                        TimeSource::from_primitive(0xa0), // TODO implement time_source: TimeSource,
                    );

                let announce_message_encode = announce_message.serialize_vec().unwrap();
                self.nc_port.send(&announce_message_encode);

                Ok(())
            }
            _ => Err(PortError::InvalidState),
        }
    }

    /// Send a sync message
    pub fn send_sync_message(&mut self, current_time: Instant) -> Result<()> {
        match &mut self.port_ds.port_state {
            PortState::Master(master) => {
                let sync_message = MessageBuilder::new()
                    .sequence_id(master.sync_seq_ids.generate())
                    .source_port_identity(self.port_ds.port_identity)
                    .sync_message(Timestamp::from(current_time));

                let sync_message_encode = sync_message.serialize_vec().unwrap();
                self.tc_port.send(&sync_message_encode);

                Ok(())
            }
            _ => Err(PortError::InvalidState),
        }
    }

    /// Send a follow up message
    pub fn send_follow_up_message(&mut self, current_time: Instant) -> Result<()> {
        match &mut self.port_ds.port_state {
            PortState::Master(master) => {
                let follow_up_message = MessageBuilder::new()
                    .sequence_id(master.sync_seq_ids.generate())
                    .source_port_identity(self.port_ds.port_identity)
                    .follow_up_message(Timestamp::from(current_time));

                let follow_up_message_encode = follow_up_message.serialize_vec().unwrap();
                self.nc_port.send(&follow_up_message_encode);

                Ok(())
            }
            _ => Err(PortError::InvalidState),
        }
    }

    pub fn handle_network(
        &mut self,
        packet: &NetworkPacket,
        current_time: Instant,
        default_ds: &DefaultDS,
    ) -> Result<()> {
        let message = Message::deserialize(&packet.data)?;

        if message.header().sdo_id() == default_ds.sdo_id
            && message.header().domain_number() == default_ds.domain_number
        {
            match &mut self.port_ds.port_state {
                PortState::Slave(state) => state.handle_message(
                    message,
                    current_time,
                    &mut self.tc_port,
                    self.port_ds.port_identity,
                )?,
                PortState::Master(master) => master.handle_message(
                    message,
                    current_time,
                    &mut self.nc_port,
                    self.port_ds.port_identity,
                )?,
                _ => unimplemented!(),
            }

            if let Message::Announce(announce) = message {
                self.bmca
                    .register_announce_message(&announce, current_time.into());

                // When an announce message is received, restart announce receipt timeout timer
                self.announce_timeout_watch
                    .set_alarm(Duration::from_log_interval(
                        self.port_ds.announce_receipt_timeout as i8
                            * self.port_ds.log_announce_interval,
                    ));
            }
        }

        Ok(())
    }

    pub fn extract_measurement(&mut self) -> Result<Measurement> {
        match &mut self.port_ds.port_state {
            PortState::Slave(state) => {
                let measurement = state.extract_measurement()?;
                Ok(measurement)
            }
            _ => Err(PortError::InvalidState),
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
        let own_data = DefaultDS::new_oc(
            self.port_ds.port_identity.clock_identity,
            default_ds.priority_1,
            default_ds.priority_2,
            0,
            true,
            1337,
        );

        let recommended_state = Bmca::calculate_recommended_state(
            &own_data,
            best_global_announce_message,
            best_port_announce_message,
            &self.port_ds.port_state,
        );

        if let Some(recommended_state) = recommended_state {
            self.handle_recommended_state(&recommended_state);
            #[allow(clippy::single_match)]
            match &recommended_state {
                RecommendedState::S1(announce_message) => {
                    *time_properties_ds = announce_message.time_properties();
                }
                _ => {}
            }
        }
    }

    pub fn announce_interval(&self) -> Duration {
        Duration::from_log_interval(self.port_ds.log_announce_interval)
    }

    pub fn handle_send_timestamp(&mut self, id: usize, timestamp: Instant) -> Result<()> {
        match &mut self.port_ds.port_state {
            PortState::Slave(state) => {
                state.handle_send_timestamp(id, timestamp)?;
                Ok(())
            }
            _ => Err(PortError::InvalidState),
        }
    }

    fn handle_recommended_state(&mut self, recommended_state: &RecommendedState) {
        let log_announce_interval = self.port_ds.log_announce_interval;
        let log_sync_interval = self.port_ds.log_sync_interval;

        match recommended_state {
            // TODO set things like steps_removed once they are added
            // TODO make sure states are complete
            RecommendedState::S1(announce_message) => match &mut self.port_ds.port_state {
                PortState::Listening => {
                    self.port_ds.port_state = PortState::Slave(SlaveState::new(
                        announce_message.header().source_port_identity(),
                    ));

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
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

                    // Stop MASTER watches
                    self.announce_watch.clear();
                    self.sync_watch.clear();

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
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
            RecommendedState::M2(default_ds) => match &self.port_ds.port_state {
                // Stay master
                PortState::Master(_) => (),

                // Otherwise become master
                _ => {
                    // Stop the announce timeout alarm
                    self.announce_timeout_watch.clear();

                    self.port_ds.port_state = PortState::Master(MasterState::new());

                    log::info!("New state for port: Master");

                    // Start sending announce messages
                    self.announce_watch
                        .set_alarm(Duration::from_log_interval(log_announce_interval));

                    // Start sending sync messages
                    self.sync_watch
                        .set_alarm(Duration::from_log_interval(log_sync_interval));
                }
            },

            // All other cases
            _ => match &mut self.port_ds.port_state {
                PortState::Listening => {
                    // Ignore
                }

                _ => {
                    self.port_ds.port_state = PortState::Listening;

                    // Stop MASTER watches
                    self.announce_watch.clear();
                    self.sync_watch.clear();

                    // Restart announce receipt timeout timer
                    self.announce_timeout_watch
                        .set_alarm(Duration::from_log_interval(
                            self.port_ds.announce_receipt_timeout as i8
                                * self.port_ds.log_announce_interval,
                        ));

                    log::info!("New state for port: Listening");
                }
            },
        }
    }
}
