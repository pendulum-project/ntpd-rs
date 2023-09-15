//! Implementation of the [ForeignMasterList]

use arrayvec::ArrayVec;

use crate::{
    datastructures::{
        common::{PortIdentity, TimeInterval},
        messages::{AnnounceMessage, Header},
    },
    time::Duration,
};

/// The time window in which announce messages are valid.
/// To get the real window, multiply it with the announce interval of the port.
const FOREIGN_MASTER_TIME_WINDOW: u16 = 4;

/// This is the amount of announce messages that must have been received within
/// the time window for a foreign master to be valid
const FOREIGN_MASTER_THRESHOLD: usize = 2;

/// The maximum amount of announce message to store within the time window
const MAX_ANNOUNCE_MESSAGES: usize = 8;

/// The maximum amount of foreign masters to store at the same time
const MAX_FOREIGN_MASTERS: usize = 8;

#[derive(Debug)]
pub struct ForeignMaster {
    foreign_master_port_identity: PortIdentity,
    // Must have a capacity of at least 2
    announce_messages: ArrayVec<ForeignAnnounceMessage, MAX_ANNOUNCE_MESSAGES>,
}

#[derive(Debug)]
pub(crate) struct ForeignAnnounceMessage {
    pub(crate) header: Header,
    pub(crate) message: AnnounceMessage,
    pub(crate) age: Duration,
}

impl ForeignMaster {
    fn new(header: Header, announce_message: AnnounceMessage) -> Self {
        let message = ForeignAnnounceMessage {
            header,
            message: announce_message,
            age: Duration::ZERO,
        };

        let mut messages = ArrayVec::<_, MAX_ANNOUNCE_MESSAGES>::new();
        messages.push(message);

        Self {
            foreign_master_port_identity: announce_message.header.source_port_identity,
            announce_messages: messages,
        }
    }

    fn foreign_master_port_identity(&self) -> PortIdentity {
        self.foreign_master_port_identity
    }

    /// Removes all messages that fall outside of the
    /// [FOREIGN_MASTER_TIME_WINDOW].
    ///
    /// Returns true if this foreign master has no more announce messages left.
    fn purge_old_messages(&mut self, announce_interval: TimeInterval) -> bool {
        let cutoff_age = Duration::from(announce_interval) * FOREIGN_MASTER_TIME_WINDOW;
        self.announce_messages.retain(|m| m.age < cutoff_age);

        self.announce_messages.is_empty()
    }

    fn register_announce_message(
        &mut self,
        header: Header,
        announce_message: AnnounceMessage,
        announce_interval: TimeInterval,
        age: Duration,
    ) {
        self.purge_old_messages(announce_interval);

        let new_message = ForeignAnnounceMessage {
            header,
            message: announce_message,
            age,
        };

        // Try to add new message; otherwise remove the first message and then add
        if let Err(e) = self.announce_messages.try_push(new_message) {
            self.announce_messages.remove(0);
            self.announce_messages.push(e.element());
        }
    }

    fn step_age(&mut self, step: Duration, announce_interval: TimeInterval) -> bool {
        for message in &mut self.announce_messages {
            message.age += step;
        }

        self.purge_old_messages(announce_interval)
    }
}

#[derive(Debug)]
pub(crate) struct ForeignMasterList {
    // Must have a capacity of at least 5
    foreign_masters: ArrayVec<ForeignMaster, MAX_FOREIGN_MASTERS>,
    own_port_announce_interval: TimeInterval,
    own_port_identity: PortIdentity,
}

impl ForeignMasterList {
    /// - `port_announce_interval`: The time interval derived from the
    ///   PortDS.log_announce_interval
    /// - `port_identity`: The identity of the port for which this list is used
    pub(crate) fn new(
        own_port_announce_interval: TimeInterval,
        own_port_identity: PortIdentity,
    ) -> Self {
        Self {
            foreign_masters: ArrayVec::<ForeignMaster, MAX_FOREIGN_MASTERS>::new(),
            own_port_announce_interval,
            own_port_identity,
        }
    }

    pub(crate) fn step_age(&mut self, step: Duration) {
        for i in (0..self.foreign_masters.len()).rev() {
            // Purge the old timestamps so we can check the FOREIGN_MASTER_THRESHOLD
            if self.foreign_masters[i].step_age(step, self.own_port_announce_interval) {
                // There are no announce messages left, so let's remove this foreign master
                self.foreign_masters.remove(i);
                continue;
            }
        }
    }

    /// Takes the qualified announce message of all foreign masters that have
    /// one
    pub(crate) fn take_qualified_announce_messages(
        &mut self,
    ) -> impl Iterator<Item = ForeignAnnounceMessage> {
        let mut qualified_foreign_masters = ArrayVec::<_, MAX_FOREIGN_MASTERS>::new();

        for i in (0..self.foreign_masters.len()).rev() {
            // A foreign master must have at least FOREIGN_MASTER_THRESHOLD messages in the
            // last FOREIGN_MASTER_TIME_WINDOW to be qualified, so we filter out
            // any that don't have that
            if self.foreign_masters[i].announce_messages.len() > FOREIGN_MASTER_THRESHOLD {
                // Only the most recent announce message is qualified, so we remove that one
                // from the list
                let last_index = self.foreign_masters[i].announce_messages.len() - 1;
                qualified_foreign_masters
                    .push(self.foreign_masters[i].announce_messages.remove(last_index));
                continue;
            }
        }

        qualified_foreign_masters.into_iter()
    }

    pub(crate) fn register_announce_message(
        &mut self,
        header: &Header,
        announce_message: &AnnounceMessage,
        age: Duration,
    ) {
        if !self.is_announce_message_qualified(announce_message) {
            // We don't want to store unqualified messages
            return;
        }

        let port_announce_interval = self.own_port_announce_interval;

        // Is the foreign master that the message represents already known?
        if let Some(foreign_master) =
            self.get_foreign_master_mut(announce_message.header.source_port_identity)
        {
            // Yes, so add the announce message to it
            foreign_master.register_announce_message(
                *header,
                *announce_message,
                port_announce_interval,
                age,
            );
        } else {
            // No, insert a new foreign master, if there is room in the array
            if self.foreign_masters.len() < MAX_FOREIGN_MASTERS {
                self.foreign_masters
                    .push(ForeignMaster::new(*header, *announce_message));
            }
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
        let source_identity = announce_message.header.source_port_identity;

        // 1. The message must not come from our own ptp instance. Since every instance
        // only has 1 clock, we can check the clock identity. That must be
        // different.
        if source_identity.clock_identity == self.own_port_identity.clock_identity {
            return false;
        }

        // 2. The announce message must be newer than the one(s) we already have
        // We can check the sequence id for that (with some logic for u16 rollover)
        if let Some(foreign_master) = self.get_foreign_master(source_identity) {
            if let Some(last_announce_message) = foreign_master.announce_messages.last() {
                let announce_sequence_id = announce_message.header.sequence_id;
                let last_sequence_id = last_announce_message.header.sequence_id;

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
        if announce_message.steps_removed >= 255 {
            return false;
        }

        // 4. The announce message may not be from a foreign master with fewer messages
        // than FOREIGN_MASTER_THRESHOLD, but that is handled in the
        // `take_qualified_announce_messages` method.

        // Otherwise, the announce message is qualified
        true
    }
}
