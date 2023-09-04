use serde::{Deserialize, Serialize};

use crate::{
    config::SynchronizationConfig,
    identifiers::ReferenceId,
    packet::NtpLeapIndicator,
    peer::PeerSnapshot,
    time_types::{NtpDuration, PollInterval},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeSnapshot {
    /// Desired poll interval
    pub poll_interval: PollInterval,
    /// Precision of the local clock
    pub precision: NtpDuration,
    /// Current root delay
    pub root_delay: NtpDuration,
    /// Current root dispersion
    pub root_dispersion: NtpDuration,
    /// Current leap indicator state
    pub leap_indicator: NtpLeapIndicator,
    /// Total amount that the clock has stepped
    pub accumulated_steps: NtpDuration,
}

impl Default for TimeSnapshot {
    fn default() -> Self {
        Self {
            poll_interval: PollInterval::default(),
            precision: NtpDuration::from_exponent(-18),
            root_delay: NtpDuration::ZERO,
            root_dispersion: NtpDuration::ZERO,
            leap_indicator: NtpLeapIndicator::Unknown,
            accumulated_steps: NtpDuration::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SystemSnapshot {
    /// Log of the precision of the local clock
    pub stratum: u8,
    /// Reference ID of current primary time source
    pub reference_id: ReferenceId,
    /// Crossing this amount of stepping will cause a Panic
    pub accumulated_steps_threshold: Option<NtpDuration>,
    /// Timekeeping data
    #[serde(flatten)]
    pub time_snapshot: TimeSnapshot,
}

impl SystemSnapshot {
    pub fn update_timedata(&mut self, timedata: TimeSnapshot, config: &SynchronizationConfig) {
        self.time_snapshot = timedata;
        self.accumulated_steps_threshold = config.accumulated_step_panic_threshold;
    }

    pub fn update_used_peers(&mut self, mut used_peers: impl Iterator<Item = PeerSnapshot>) {
        if let Some(system_peer_snapshot) = used_peers.next() {
            self.stratum = system_peer_snapshot.stratum.saturating_add(1);
            self.reference_id = system_peer_snapshot.reference_id;
        }
    }
}

impl Default for SystemSnapshot {
    fn default() -> Self {
        Self {
            stratum: 16,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::time_types::PollIntervalLimits;

    use super::*;

    #[test]
    fn test_empty_peer_update() {
        let mut system = SystemSnapshot::default();

        // Should do nothing
        system.update_used_peers(std::iter::empty());

        assert_eq!(system.stratum, 16);
        assert_eq!(system.reference_id, ReferenceId::NONE);
    }

    #[test]
    fn test_peer_update() {
        let mut system = SystemSnapshot::default();

        system.update_used_peers(
            vec![
                PeerSnapshot {
                    source_id: ReferenceId::KISS_DENY,
                    our_id: ReferenceId::NONE,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 2,
                    reference_id: ReferenceId::KISS_DENY,
                },
                PeerSnapshot {
                    source_id: ReferenceId::KISS_RATE,
                    our_id: ReferenceId::KISS_RSTR,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 3,
                    reference_id: ReferenceId::NONE,
                },
            ]
            .into_iter(),
        );

        assert_eq!(system.stratum, 3);
        assert_eq!(system.reference_id, ReferenceId::KISS_DENY);
    }

    #[test]
    fn test_timedata_update() {
        let mut system = SystemSnapshot::default();

        let new_root_delay = NtpDuration::from_seconds(1.0);
        let new_accumulated_threshold = NtpDuration::from_seconds(2.0);

        let snapshot = TimeSnapshot {
            root_delay: new_root_delay,
            ..Default::default()
        };
        system.update_timedata(
            snapshot,
            &SynchronizationConfig {
                accumulated_step_panic_threshold: Some(new_accumulated_threshold),
                ..Default::default()
            },
        );

        assert_eq!(system.time_snapshot, snapshot);

        assert_eq!(
            system.accumulated_steps_threshold,
            Some(new_accumulated_threshold),
        );
    }
}
