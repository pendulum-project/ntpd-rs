//! Implementation of the best master clock algorithm [Bmca]

use super::{
    dataset_comparison::{ComparisonDataset, DatasetOrdering},
    foreign_master::ForeignMasterList,
};
use crate::{
    datastructures::{
        common::{PortIdentity, TimeInterval, Timestamp},
        datasets::DefaultDS,
        messages::AnnounceMessage,
    },
    port::state::PortState,
    time::Instant,
};

/// Object implementing the Best Master Clock Algorithm
///
/// Usage:
///
/// - Every port has its own instance.
/// - When a port receives an announce message, it has to register it with the
///   [Bmca::register_announce_message] method
/// - When it is time to run the algorithm, the ptp runtime has to take all the
///   best announce messages using [Bmca::take_best_port_announce_message]
/// - Of the resulting set, the best global one needs to be determined. This can
///   be done using [Bmca::find_best_announce_message]
/// - Then to get the recommended state for each port,
///   [Bmca::calculate_recommended_state] needs to be called
pub struct Bmca {
    foreign_master_list: ForeignMasterList,
    own_port_identity: PortIdentity,
}

impl Bmca {
    pub fn new(own_port_announce_interval: TimeInterval, own_port_identity: PortIdentity) -> Self {
        Self {
            foreign_master_list: ForeignMasterList::new(
                own_port_announce_interval,
                own_port_identity,
            ),
            own_port_identity,
        }
    }

    /// Register a received announce message to the BMC algorithm
    pub fn register_announce_message(
        &mut self,
        announce_message: &AnnounceMessage,
        current_time: Timestamp,
    ) {
        // Ignore messages comming from the same port
        if announce_message.header().source_port_identity() != self.own_port_identity {
            self.foreign_master_list
                .register_announce_message(announce_message, current_time);
        }
    }

    /// Takes the Erbest from this port
    pub fn take_best_port_announce_message(
        &mut self,
        current_time: Timestamp,
    ) -> Option<BestAnnounceMessage> {
        // Find the announce message we want to use from each foreign master that has
        // qualified messages
        let announce_messages = self
            .foreign_master_list
            .take_qualified_announce_messages(current_time);

        // The best of the foreign master messages is our erbest
        let erbest =
            Self::find_best_announce_message(announce_messages.map(|(message, timestamp)| {
                BestAnnounceMessage {
                    message,
                    timestamp,
                    identity: self.own_port_identity,
                }
            }));

        if let Some(best) = &erbest {
            // All messages that were considered have been removed from the
            // foreignmasterlist. However, the one that has been selected as the
            // Erbest must not be removed, so let's just reregister it.
            self.register_announce_message(&best.message, best.timestamp);
        }

        erbest
    }

    /// Finds the best announce message in the given iterator.
    /// The port identity in the tuple is the identity of the port that received
    /// the announce message.
    pub fn find_best_announce_message(
        announce_messages: impl IntoIterator<Item = BestAnnounceMessage>,
    ) -> Option<BestAnnounceMessage> {
        announce_messages.into_iter().reduce(|left, right| {
            match ComparisonDataset::from_announce_message(&left.message, &left.identity).compare(
                &ComparisonDataset::from_announce_message(&right.message, &right.identity),
            ) {
                DatasetOrdering::Better | DatasetOrdering::BetterByTopology => left,
                // We get errors if two announce messages are (functionally) the same, in that case
                // we just pick the newer one
                DatasetOrdering::Error1 | DatasetOrdering::Error2 => {
                    if Instant::from(left.timestamp) >= Instant::from(right.timestamp) {
                        left
                    } else {
                        right
                    }
                }
                DatasetOrdering::WorseByTopology | DatasetOrdering::Worse => right,
            }
        })
    }

    /// Calculates the recommended port state. This has to be run for every
    /// port. The PTP spec calls this the State Decision Algorithm.
    ///
    /// - `own_data`: Called 'D0' by the PTP spec. The DefaultDS data of our own
    ///   ptp instance.
    /// - `best_global_announce_message`: Called 'Ebest' by the PTP spec. This
    ///   is the best announce message and the
    /// identity of the port that received it of all of the best port announce
    /// messages.
    /// - `best_port_announce_message`: Called 'Erbest' by the PTP spec. This is
    ///   the best announce message and the
    /// identity of the port that received it of the port we are calculating the
    /// recommended state for.
    /// - `port_state`: The current state of the port we are doing the
    ///   calculation for.
    ///
    /// If None is returned, then the port should remain in the same state as it
    /// is now.
    pub fn calculate_recommended_state(
        own_data: &DefaultDS,
        best_global_announce_message: Option<BestAnnounceMessage>,
        best_port_announce_message: Option<BestAnnounceMessage>,
        port_state: &PortState,
    ) -> Option<RecommendedState> {
        let d0 = ComparisonDataset::from_own_data(own_data);
        let ebest = best_global_announce_message
            .map(|best| ComparisonDataset::from_announce_message(&best.message, &best.identity));
        let erbest = best_port_announce_message
            .map(|best| ComparisonDataset::from_announce_message(&best.message, &best.identity));

        if best_global_announce_message.is_none() && matches!(port_state, PortState::Listening) {
            return None;
        }

        if (1..=127).contains(&own_data.clock_quality.clock_class) {
            return match erbest {
                None => Some(RecommendedState::M1(*own_data)),
                Some(erbest) => {
                    if d0.compare(&erbest).is_better() {
                        Some(RecommendedState::M1(*own_data))
                    } else {
                        Some(RecommendedState::P1(
                            best_port_announce_message.unwrap().message,
                        ))
                    }
                }
            };
        }

        match &ebest {
            None => return Some(RecommendedState::M2(*own_data)),
            Some(ebest) => {
                if d0.compare(ebest).is_better() {
                    return Some(RecommendedState::M2(*own_data));
                }
            }
        }

        // If ebest was empty, then we would have returned in the previous step
        let best_global_announce_message = best_global_announce_message.unwrap();
        let ebest = ebest.unwrap();

        match erbest {
            None => Some(RecommendedState::M3(best_global_announce_message.message)),
            Some(erbest) => {
                let best_port_announce_message = best_port_announce_message.unwrap();

                if best_global_announce_message.timestamp == best_port_announce_message.timestamp {
                    Some(RecommendedState::S1(best_global_announce_message.message))
                } else if matches!(ebest.compare(&erbest), DatasetOrdering::BetterByTopology) {
                    Some(RecommendedState::P2(best_port_announce_message.message))
                } else {
                    Some(RecommendedState::M3(best_global_announce_message.message))
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BestAnnounceMessage {
    message: AnnounceMessage,
    timestamp: Timestamp,
    identity: PortIdentity,
}

#[derive(Debug)]
pub enum RecommendedState {
    M1(DefaultDS),
    M2(DefaultDS),
    M3(AnnounceMessage),
    P1(AnnounceMessage),
    P2(AnnounceMessage),
    S1(AnnounceMessage),
}
