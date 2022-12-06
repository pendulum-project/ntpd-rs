use serde::{Deserialize, Serialize};

use crate::{NtpDuration, NtpLeapIndicator, PeerSnapshot, PollInterval, ReferenceId, SystemConfig};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    pub fn update(
        &mut self,
        mut used_peers: impl Iterator<Item = PeerSnapshot>,
        timedata: TimeSnapshot,
        config: &SystemConfig,
    ) {
        self.time_snapshot = timedata;
        self.accumulated_steps_threshold = config.accumulated_threshold;
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
    use crate::PollIntervalLimits;

    use super::*;

    #[test]
    fn test_empty_update() {
        let mut system = SystemSnapshot::default();

        system.update(
            std::iter::empty(),
            TimeSnapshot {
                root_delay: NtpDuration::from_seconds(1.0),
                ..Default::default()
            },
            &SystemConfig::default(),
        );

        assert_eq!(system.stratum, 16);
        assert_eq!(system.reference_id, ReferenceId::NONE);
        assert_eq!(
            system.time_snapshot.root_delay,
            NtpDuration::from_seconds(1.0)
        );
    }

    #[test]
    fn test_update() {
        let mut system = SystemSnapshot::default();

        system.update(
            vec![
                PeerSnapshot {
                    peer_id: ReferenceId::KISS_DENY,
                    our_id: ReferenceId::NONE,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 2,
                    reference_id: ReferenceId::KISS_DENY,
                },
                PeerSnapshot {
                    peer_id: ReferenceId::KISS_RATE,
                    our_id: ReferenceId::KISS_RSTR,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 3,
                    reference_id: ReferenceId::NONE,
                },
            ]
            .into_iter(),
            TimeSnapshot {
                root_delay: NtpDuration::from_seconds(1.0),
                ..Default::default()
            },
            &SystemConfig::default(),
        );

        assert_eq!(system.stratum, 3);
        assert_eq!(system.reference_id, ReferenceId::KISS_DENY);
        assert_eq!(
            system.time_snapshot.root_delay,
            NtpDuration::from_seconds(1.0)
        );
        assert_eq!(system.time_snapshot.poll_interval, PollInterval::default());
    }
}
