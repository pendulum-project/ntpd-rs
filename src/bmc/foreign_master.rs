//! Implementation of the [ForeignMasterList]

use crate::{
    datastructures::{
        common::{PortIdentity, TimeInterval, Timestamp},
        messages::AnnounceMessage,
    },
    time::{Duration, Instant},
};

/// The time window in which announce messages are valid.
/// To get the real window, multiply it with the announce interval of the port.
const FOREIGN_MASTER_TIME_WINDOW: u16 = 4;
/// This is the amount of announce messages that must have been received within the time window
/// for a foreign master to be valid
const FOREIGN_MASTER_THRESHOLD: usize = 2;

pub struct ForeignMaster {
    foreign_master_port_identity: PortIdentity,
    // Must have a capacity of at least 2
    announce_messages: Vec<(AnnounceMessage, Timestamp)>,
}

impl ForeignMaster {
    fn new(announce_message: AnnounceMessage, current_time: Timestamp) -> Self {
        Self {
            foreign_master_port_identity: announce_message.header().source_port_identity(),
            announce_messages: Vec::from([(announce_message, current_time)]),
        }
    }

    fn foreign_master_port_identity(&self) -> PortIdentity {
        self.foreign_master_port_identity
    }

    /// Removes all messages that fall outside of the [FOREIGN_MASTER_TIME_WINDOW].
    ///
    /// Returns true if this foreign master has no more announce messages left.
    fn purge_old_messages(
        &mut self,
        current_time: Timestamp,
        announce_interval: TimeInterval,
    ) -> bool {
        let cutoff_time = Instant::from_timestamp(&current_time)
            - Duration::from_interval(&announce_interval) * FOREIGN_MASTER_TIME_WINDOW;
        self.announce_messages
            .retain(|(_, ts)| Instant::from_timestamp(ts) > cutoff_time);

        self.announce_messages.is_empty()
    }

    fn register_announce_message(
        &mut self,
        announce_message: AnnounceMessage,
        current_time: Timestamp,
        announce_interval: TimeInterval,
    ) {
        self.purge_old_messages(current_time, announce_interval);
        self.announce_messages
            .push((announce_message, current_time));
    }
}

pub struct ForeignMasterList {
    // Must have a capacity of at least 5
    foreign_masters: Vec<ForeignMaster>,
    own_port_announce_interval: TimeInterval,
    own_port_identity: PortIdentity,
}

impl ForeignMasterList {
    /// - `port_announce_interval`: The time interval derived from the PortDS.log_announce_interval
    /// - `port_identity`: The identity of the port for which this list is used
    pub fn new(own_port_announce_interval: TimeInterval, own_port_identity: PortIdentity) -> Self {
        Self {
            foreign_masters: Vec::new(),
            own_port_announce_interval,
            own_port_identity,
        }
    }

    /// Takes the qualified announce message of all foreign masters that have one
    pub fn take_qualified_announce_messages(
        &mut self,
        current_time: Timestamp,
    ) -> impl Iterator<Item = (AnnounceMessage, Timestamp)> {
        let mut qualified_foreign_masters = Vec::new();

        for i in (0..self.foreign_masters.len()).rev() {
            // Purge the old timestamps so we can check the FOREIGN_MASTER_THRESHOLD
            if self.foreign_masters[i]
                .purge_old_messages(current_time, self.own_port_announce_interval)
            {
                // There are no announce messages left, so let's remove this foreign master
                self.foreign_masters.remove(i);
                continue;
            }

            // A foreign master must have at least FOREIGN_MASTER_THRESHOLD messages in the last FOREIGN_MASTER_TIME_WINDOW
            // to be qualified, so we filter out any that don't have that
            if self.foreign_masters[i].announce_messages.len() > FOREIGN_MASTER_THRESHOLD {
                // Only the most recent announce message is qualified, so we remove that one from the list
                let last_index = self.foreign_masters[i].announce_messages.len() - 1;
                qualified_foreign_masters
                    .push(self.foreign_masters[i].announce_messages.remove(last_index));
                continue;
            }
        }

        qualified_foreign_masters.into_iter()
    }

    pub fn register_announce_message(
        &mut self,
        announce_message: &AnnounceMessage,
        current_time: Timestamp,
    ) {
        if !self.is_announce_message_qualified(announce_message) {
            // We don't want to store unqualified messages
            return;
        }

        let port_announce_interval = self.own_port_announce_interval;

        // Is the foreign master that the message represents already known?
        if let Some(foreign_master) =
            self.get_foreign_master_mut(announce_message.header().source_port_identity())
        {
            // Yes, so add the announce message to it
            foreign_master.register_announce_message(
                *announce_message,
                current_time,
                port_announce_interval,
            );
        } else {
            // No, insert a new foreign master
            self.foreign_masters
                .push(ForeignMaster::new(*announce_message, current_time));
        }
    }

    fn get_foreign_master_mut(
        &mut self,
        port_identity: PortIdentity,
    ) -> Option<&mut ForeignMaster> {
        self.foreign_masters
            .iter_mut()
            .find(|fm| fm.foreign_master_port_identity() == port_identity)
    }

    fn get_foreign_master(&self, port_identity: PortIdentity) -> Option<&ForeignMaster> {
        self.foreign_masters
            .iter()
            .find(|fm| fm.foreign_master_port_identity() == port_identity)
    }

    fn is_announce_message_qualified(&self, announce_message: &AnnounceMessage) -> bool {
        let source_identity = announce_message.header().source_port_identity();

        // 1. The message must not come from our own ptp instance. Since every instance only has 1 clock,
        // we can check the clock identity. That must be different.
        if source_identity.clock_identity == self.own_port_identity.clock_identity {
            return false;
        }

        // 2. The announce message must be newer than the one(s) we already have
        // We can check the sequence id for that (with some logic for u16 rollover)
        if let Some(foreign_master) = self.get_foreign_master(source_identity) {
            if let Some((last_announce_message, _)) = foreign_master.announce_messages.last() {
                let announce_sequence_id = announce_message.header().sequence_id();
                let last_sequence_id = last_announce_message.header().sequence_id();

                if last_sequence_id >= FOREIGN_MASTER_TIME_WINDOW {
                    if announce_sequence_id < last_sequence_id {
                        return false;
                    }
                } else if announce_sequence_id - last_sequence_id
                    > u16::MAX - FOREIGN_MASTER_TIME_WINDOW
                {
                    return false;
                }
            }
        }

        // 3. The announce message must not have a steps removed of 255 and greater
        if announce_message.steps_removed() >= 255 {
            return false;
        }

        // 4. The announce message may not be from a foreign master with fewer messages
        // than FOREIGN_MASTER_THRESHOLD, but that is handled in the `take_qualified_announce_messages` method.

        // Otherwise, the announce message is qualified
        true
    }
}
