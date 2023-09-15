//! Implementation of the best master clock algorithm [Bmca]

use core::cmp::Ordering;

use super::{
    dataset_comparison::{ComparisonDataset, DatasetOrdering},
    foreign_master::ForeignMasterList,
};
use crate::{
    datastructures::{
        common::{PortIdentity, TimeInterval},
        datasets::DefaultDS,
        messages::{AnnounceMessage, Header},
    },
    port::state::PortState,
    Duration,
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
#[derive(Debug)]
pub(crate) struct Bmca {
    foreign_master_list: ForeignMasterList,
    own_port_identity: PortIdentity,
}

impl Bmca {
    pub(crate) fn new(
        own_port_announce_interval: TimeInterval,
        own_port_identity: PortIdentity,
    ) -> Self {
        Self {
            foreign_master_list: ForeignMasterList::new(
                own_port_announce_interval,
                own_port_identity,
            ),
            own_port_identity,
        }
    }

    pub(crate) fn step_age(&mut self, step: Duration) {
        self.foreign_master_list.step_age(step);
    }

    /// Register a received announce message to the BMC algorithm
    pub(crate) fn register_announce_message(
        &mut self,
        header: &Header,
        announce_message: &AnnounceMessage,
    ) {
        // Ignore messages comming from the same port
        if announce_message.header.source_port_identity != self.own_port_identity {
            self.foreign_master_list.register_announce_message(
                header,
                announce_message,
                Duration::ZERO,
            );
        }
    }

    pub(crate) fn reregister_announce_message(
        &mut self,
        header: &Header,
        announce_message: &AnnounceMessage,
        age: Duration,
    ) {
        // Ignore messages comming from the same port
        if announce_message.header.source_port_identity != self.own_port_identity {
            self.foreign_master_list
                .register_announce_message(header, announce_message, age);
        }
    }

    /// Takes the Erbest from this port
    pub(crate) fn take_best_port_announce_message(&mut self) -> Option<BestAnnounceMessage> {
        // Find the announce message we want to use from each foreign master that has
        // qualified messages
        let announce_messages = self.foreign_master_list.take_qualified_announce_messages();

        // The best of the foreign master messages is our erbest
        let erbest = Self::find_best_announce_message(announce_messages.map(|message| {
            BestAnnounceMessage {
                header: message.header,
                message: message.message,
                age: message.age,
                identity: self.own_port_identity,
            }
        }));

        if let Some(best) = &erbest {
            // All messages that were considered have been removed from the
            // foreignmasterlist. However, the one that has been selected as the
            // Erbest must not be removed, so let's just reregister it.
            self.reregister_announce_message(&best.header, &best.message, best.age);
        }

        erbest
    }

    /// Finds the best announce message in the given iterator.
    /// The port identity in the tuple is the identity of the port that received
    /// the announce message.
    pub(crate) fn find_best_announce_message(
        announce_messages: impl IntoIterator<Item = BestAnnounceMessage>,
    ) -> Option<BestAnnounceMessage> {
        announce_messages
            .into_iter()
            .max_by(BestAnnounceMessage::compare)
    }

    fn compare_d0_best(
        d0: &ComparisonDataset,
        opt_best: Option<BestAnnounceMessage>,
    ) -> MessageComparison {
        match opt_best {
            None => MessageComparison::Better,
            Some(best) => {
                let dataset =
                    ComparisonDataset::from_announce_message(&best.message, &best.identity);

                match d0.compare(&dataset).as_ordering() {
                    Ordering::Less => MessageComparison::Worse(best),
                    Ordering::Equal => MessageComparison::Same,
                    Ordering::Greater => MessageComparison::Better,
                }
            }
        }
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
    pub(crate) fn calculate_recommended_state<F>(
        own_data: &DefaultDS,
        best_global_announce_message: Option<BestAnnounceMessage>,
        best_port_announce_message: Option<BestAnnounceMessage>,
        port_state: &PortState<F>,
    ) -> Option<RecommendedState> {
        if best_global_announce_message.is_none() && matches!(port_state, PortState::Listening) {
            None
        } else if (1..=127).contains(&own_data.clock_quality.clock_class) {
            // only consider the best message of the port
            Some(Self::calculate_recommended_state_low_class(
                own_data,
                best_port_announce_message,
            ))
        } else {
            // see if the best of this port is better than the global best
            Some(Self::calculate_recommended_state_high_class(
                own_data,
                best_global_announce_message,
                best_port_announce_message,
            ))
        }
    }

    fn calculate_recommended_state_low_class(
        own_data: &DefaultDS,
        best_port_announce_message: Option<BestAnnounceMessage>,
    ) -> RecommendedState {
        let d0 = ComparisonDataset::from_own_data(own_data);

        match Self::compare_d0_best(&d0, best_port_announce_message) {
            MessageComparison::Better => RecommendedState::M1(*own_data),
            MessageComparison::Same => RecommendedState::M1(*own_data),
            MessageComparison::Worse(port) => RecommendedState::P1(port.message),
        }
    }

    fn calculate_recommended_state_high_class(
        own_data: &DefaultDS,
        best_global_announce_message: Option<BestAnnounceMessage>,
        best_port_announce_message: Option<BestAnnounceMessage>,
    ) -> RecommendedState {
        let d0 = ComparisonDataset::from_own_data(own_data);

        match Self::compare_d0_best(&d0, best_global_announce_message) {
            MessageComparison::Better => RecommendedState::M2(*own_data),
            MessageComparison::Same => RecommendedState::M2(*own_data),
            MessageComparison::Worse(global_message) => match best_port_announce_message {
                None => RecommendedState::M3(global_message.message),
                Some(port_message) => Self::compare_global_and_port(global_message, port_message),
            },
        }
    }

    fn compare_global_and_port(
        global_message: BestAnnounceMessage,
        port_message: BestAnnounceMessage,
    ) -> RecommendedState {
        if global_message == port_message {
            // effectively, E_best == E_rbest
            RecommendedState::S1(global_message.message)
        } else {
            let ebest = ComparisonDataset::from_announce_message(
                &global_message.message,
                &global_message.identity,
            );

            let erbest = ComparisonDataset::from_announce_message(
                &port_message.message,
                &port_message.identity,
            );

            // E_best better by topology than E_rbest
            if matches!(ebest.compare(&erbest), DatasetOrdering::BetterByTopology) {
                RecommendedState::P2(port_message.message)
            } else {
                RecommendedState::M3(global_message.message)
            }
        }
    }
}

#[derive(Debug)]
enum MessageComparison {
    Better,
    Same,
    Worse(BestAnnounceMessage),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BestAnnounceMessage {
    header: Header,
    message: AnnounceMessage,
    age: Duration,
    identity: PortIdentity,
}

impl BestAnnounceMessage {
    fn compare(&self, other: &Self) -> Ordering {
        // use the age as a tie-break if needed (prefer newer messages)
        let tie_break = other.age.cmp(&self.age);
        self.compare_dataset(other).as_ordering().then(tie_break)
    }

    fn compare_dataset(&self, other: &Self) -> DatasetOrdering {
        let data1 = ComparisonDataset::from_announce_message(&self.message, &self.identity);
        let data2 = ComparisonDataset::from_announce_message(&other.message, &other.identity);

        data1.compare(&data2)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecommendedState {
    M1(DefaultDS),
    M2(DefaultDS),
    M3(AnnounceMessage),
    P1(AnnounceMessage),
    P2(AnnounceMessage),
    S1(AnnounceMessage),
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::{
        config::InstanceConfig,
        datastructures::messages::{Header, PtpVersion},
        ClockIdentity,
    };

    fn default_announce_message_header() -> Header {
        Header {
            sdo_id: Default::default(),
            version: PtpVersion::new(2, 1).unwrap(),
            domain_number: Default::default(),
            alternate_master_flag: false,
            two_step_flag: false,
            unicast_flag: false,
            ptp_profile_specific_1: false,
            ptp_profile_specific_2: false,
            leap61: false,
            leap59: false,
            current_utc_offset_valid: false,
            ptp_timescale: false,
            time_tracable: false,
            frequency_tracable: false,
            synchronization_uncertain: false,
            correction_field: Default::default(),
            source_port_identity: Default::default(),
            sequence_id: Default::default(),
            log_message_interval: Default::default(),
        }
    }

    fn default_announce_message() -> AnnounceMessage {
        AnnounceMessage {
            header: default_announce_message_header(),
            origin_timestamp: Default::default(),
            current_utc_offset: Default::default(),
            grandmaster_priority_1: Default::default(),
            grandmaster_clock_quality: Default::default(),
            grandmaster_priority_2: Default::default(),
            grandmaster_identity: Default::default(),
            steps_removed: Default::default(),
            time_source: Default::default(),
        }
    }

    fn default_best_announce_message() -> BestAnnounceMessage {
        let header = default_announce_message_header();
        let message = default_announce_message();

        let identity = PortIdentity {
            clock_identity: ClockIdentity([0; 8]),
            port_number: 0,
        };

        BestAnnounceMessage {
            header,
            message,
            age: Duration::ZERO,
            identity,
        }
    }

    #[test]
    fn best_announce_message_compare_equal() {
        let message1 = default_best_announce_message();
        let message2 = default_best_announce_message();

        let ordering = message1.compare_dataset(&message2).as_ordering();
        assert_eq!(ordering, Ordering::Equal);
    }

    #[test]
    fn best_announce_message_compare() {
        let mut message1 = default_best_announce_message();
        let mut message2 = default_best_announce_message();

        // identities are different
        message1.message.grandmaster_identity = ClockIdentity([0; 8]);
        message2.message.grandmaster_identity = ClockIdentity([1; 8]);

        // higher priority is worse in this ordering
        message1.message.grandmaster_priority_1 = 0;
        message2.message.grandmaster_priority_1 = 1;

        // hence we expect message1 to be better than message2
        assert_eq!(message1.compare_dataset(&message2), DatasetOrdering::Better);
        assert_eq!(message2.compare_dataset(&message1), DatasetOrdering::Worse);

        assert_eq!(message1.compare(&message2), Ordering::Greater);
        assert_eq!(message2.compare(&message1), Ordering::Less);
    }

    #[test]
    fn best_announce_message_max_tie_break() {
        let mut message1 = default_best_announce_message();
        let mut message2 = default_best_announce_message();

        message1.age = Duration::from_micros(2);
        message2.age = Duration::from_micros(1);

        // the newest message should be preferred
        assert!(message2.age < message1.age);

        let ordering = message1.compare_dataset(&message2).as_ordering();
        assert_eq!(ordering, Ordering::Equal);

        // so message1 is lower in the ordering than message2
        assert_eq!(message1.compare(&message2), Ordering::Less)
    }

    fn default_own_data() -> DefaultDS {
        let clock_identity = Default::default();
        let priority_1 = 0;
        let priority_2 = 0;
        let domain_number = 0;
        let slave_only = false;
        let sdo_id = Default::default();

        DefaultDS::new(InstanceConfig {
            clock_identity,
            priority_1,
            priority_2,
            domain_number,
            slave_only,
            sdo_id,
        })
    }

    #[test]
    fn recommend_state_no_best() {
        let mut own_data = default_own_data();

        // zero is reserved
        own_data.clock_quality.clock_class = 1;

        let call = |port_state: &PortState<()>| {
            Bmca::calculate_recommended_state(&own_data, None, None, port_state)
        };

        // when E_best is empty and the port state is listening, it should remain
        // listening
        assert!(call(&PortState::Listening).is_none());

        // otherwise it should return a recommendation
        assert!(matches!(
            call(&PortState::Passive),
            Some(RecommendedState::M1(_))
        ))
    }

    #[test]
    fn recommend_state_low_class() {
        let clock_identity = Default::default();
        let priority_1 = 0;
        let priority_2 = 0;
        let domain_number = 0;
        let slave_only = false;
        let sdo_id = Default::default();

        let mut own_data = DefaultDS::new(InstanceConfig {
            clock_identity,
            priority_1,
            priority_2,
            domain_number,
            slave_only,
            sdo_id,
        });

        own_data.clock_quality.clock_class = 1;
        assert!((1..=127).contains(&own_data.clock_quality.clock_class));

        // D0 is the same as E_rbest; this is unreachable in practice, but we return M1
        // in this case
        let d0 = ComparisonDataset::from_own_data(&own_data);
        let port_message = default_best_announce_message();

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(port_message)),
            MessageComparison::Same
        ));

        assert_eq!(
            Some(RecommendedState::M1(own_data)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                None,
                Some(port_message),
                &PortState::Passive,
            )
        );

        // D0 is the better than E_rbest; M1 is expected
        let d0 = ComparisonDataset::from_own_data(&own_data);
        let mut port_message = default_best_announce_message();

        port_message.identity.port_number = 1;

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(port_message)),
            MessageComparison::Better
        ));

        assert_eq!(
            Some(RecommendedState::M1(own_data)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                None,
                Some(port_message),
                &PortState::Passive,
            )
        );

        // D0 is NOT better than E_rbest; P1 is expected
        let mut own_data = own_data;

        let mut port_message = default_best_announce_message();

        own_data.clock_identity = ClockIdentity([0; 8]);
        port_message.message.grandmaster_identity = ClockIdentity([1; 8]);

        own_data.priority_1 = 1;
        port_message.message.grandmaster_priority_1 = 0;

        let d0 = ComparisonDataset::from_own_data(&own_data);

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(port_message)),
            MessageComparison::Worse(_)
        ));

        assert_eq!(
            Some(RecommendedState::P1(port_message.message)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                None,
                Some(port_message),
                &PortState::Passive,
            )
        );
    }

    #[test]
    fn recommend_state_high() {
        let mut own_data = default_own_data();

        own_data.clock_quality.clock_class = 128;
        assert!(!(1..=127).contains(&own_data.clock_quality.clock_class));

        // D0 is the same as E_best; this is unreachable in practice, but we return M2
        // in this case
        let d0 = ComparisonDataset::from_own_data(&own_data);
        let global_message = default_best_announce_message();

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(global_message)),
            MessageComparison::Same
        ));

        assert_eq!(
            Some(RecommendedState::M2(own_data)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                Some(global_message),
                None,
                &PortState::Passive,
            )
        );

        // D0 is better than E_best; M1 is expected
        let d0 = ComparisonDataset::from_own_data(&own_data);
        let mut global_message = default_best_announce_message();

        global_message.identity.port_number = 1;

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(global_message)),
            MessageComparison::Better
        ));

        assert_eq!(
            Some(RecommendedState::M2(own_data)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                Some(global_message),
                None,
                &PortState::Passive,
            )
        );

        // D0 is NOT better than E_best
        let mut own_data = own_data;

        let mut global_message = default_best_announce_message();

        own_data.clock_identity = ClockIdentity([0; 8]);
        global_message.message.grandmaster_identity = ClockIdentity([1; 8]);

        own_data.priority_1 = 1;
        global_message.message.grandmaster_priority_1 = 0;

        let d0 = ComparisonDataset::from_own_data(&own_data);

        assert!(matches!(
            Bmca::compare_d0_best(&d0, Some(global_message)),
            MessageComparison::Worse(_)
        ));

        assert_eq!(
            Some(RecommendedState::S1(global_message.message)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                Some(global_message),
                Some(global_message),
                &PortState::Passive,
            )
        );
    }

    #[test]
    fn ebest_better_by_topology_no() {
        let mut own_data = default_own_data();
        let mut global_message = default_best_announce_message();

        // take the erest branch
        own_data.clock_quality.clock_class = 128;

        own_data.clock_identity = ClockIdentity([0; 8]);
        global_message.message.grandmaster_identity = ClockIdentity([1; 8]);

        own_data.priority_1 = 1;
        global_message.message.grandmaster_priority_1 = 0;

        let mut port_message = global_message;

        global_message.age = Duration::from_micros(4);
        port_message.age = Duration::from_micros(2);

        let ebest = ComparisonDataset::from_announce_message(
            &global_message.message,
            &global_message.identity,
        );

        let erbest =
            ComparisonDataset::from_announce_message(&port_message.message, &port_message.identity);

        assert!(!matches!(
            ebest.compare(&erbest),
            DatasetOrdering::BetterByTopology
        ));

        assert_eq!(
            Some(RecommendedState::M3(global_message.message)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                Some(global_message),
                Some(port_message),
                &PortState::Passive,
            )
        );
    }

    #[test]
    fn ebest_better_by_topology_yes() {
        let mut own_data = default_own_data();
        let mut global_message = default_best_announce_message();

        // take the erest branch
        own_data.clock_quality.clock_class = 128;

        own_data.clock_identity = ClockIdentity([0; 8]);
        global_message.message.grandmaster_identity = ClockIdentity([1; 8]);

        own_data.priority_1 = 1;
        global_message.message.grandmaster_priority_1 = 0;

        let mut port_message = global_message;

        global_message.age = Duration::from_micros(4);
        port_message.age = Duration::from_micros(2);

        let ebest = ComparisonDataset::from_announce_message(
            &global_message.message,
            &global_message.identity,
        );

        let erbest =
            ComparisonDataset::from_announce_message(&port_message.message, &port_message.identity);

        assert!(!matches!(
            ebest.compare(&erbest),
            DatasetOrdering::BetterByTopology
        ));

        assert_eq!(
            Some(RecommendedState::M3(global_message.message)),
            Bmca::calculate_recommended_state::<()>(
                &own_data,
                Some(global_message),
                Some(port_message),
                &PortState::Passive,
            )
        );
    }
}
