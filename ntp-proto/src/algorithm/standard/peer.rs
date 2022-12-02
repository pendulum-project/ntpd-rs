use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::filter::{FilterTuple, LastMeasurements};
use crate::{
    AcceptSynchronizationError, FrequencyTolerance, Measurement, NtpDuration, NtpInstant,
    NtpLeapIndicator, NtpPacket, PollInterval, SystemConfig, TimeSnapshot,
};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub(super) struct PeerStatistics {
    pub offset: NtpDuration,
    pub delay: NtpDuration,

    pub dispersion: NtpDuration,
    pub jitter: f64,
}

#[derive(Debug, Clone)]
pub(super) struct PeerTimeState {
    pub statistics: PeerStatistics,
    pub last_measurements: LastMeasurements,
    pub last_packet: NtpPacket<'static>,
    pub time: NtpInstant,
}

impl PeerTimeState {
    pub fn update(
        &mut self,
        measurement: Measurement,
        packet: NtpPacket,
        system: TimeSnapshot,
        system_config: &SystemConfig,
    ) -> Option<()> {
        let filter_input = FilterTuple::from_measurement(
            measurement,
            &packet,
            system.precision,
            system_config.frequency_tolerance,
        );

        self.last_packet = packet.into_owned();

        let updated = self.last_measurements.step(
            filter_input,
            self.time,
            system.leap_indicator,
            system.precision,
            system_config.frequency_tolerance,
        );

        if let Some((statistics, time)) = updated {
            self.statistics = statistics;
            self.time = time;

            Some(())
        } else {
            None
        }
    }

    /// Root distance without the `(local_clock_time - self.time) * PHI` term
    fn root_distance_without_time(&self) -> NtpDuration {
        NtpDuration::MIN_DISPERSION.max(self.last_packet.root_delay() + self.statistics.delay)
            / 2i64
            + self.last_packet.root_dispersion()
            + self.statistics.dispersion
            + NtpDuration::from_seconds(self.statistics.jitter)
    }

    /// The root synchronization distance is the maximum error due to
    /// all causes of the local clock relative to the primary server.
    /// It is defined as half the total delay plus total dispersion
    /// plus peer jitter.
    #[cfg(test)]
    fn root_distance(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
    ) -> NtpDuration {
        self.root_distance_without_time()
            + NtpInstant::abs_diff(local_clock_time, self.time) * frequency_tolerance
    }

    /// reset just the measurement data, the poll and connection data is unchanged
    pub fn reset_measurements(&mut self) {
        self.statistics = Default::default();
        self.last_measurements = LastMeasurements::new(self.time);
        self.last_packet = Default::default();
    }

    #[cfg(test)]
    pub fn test_timestate(instant: NtpInstant) -> Self {
        PeerTimeState {
            statistics: Default::default(),
            last_measurements: LastMeasurements::new(instant),
            last_packet: Default::default(),
            time: instant,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PeerTimeSnapshot {
    pub root_distance_without_time: NtpDuration,
    pub statistics: PeerStatistics,

    pub time: NtpInstant,
    pub stratum: u8,

    pub leap_indicator: NtpLeapIndicator,
    pub root_delay: NtpDuration,
    pub root_dispersion: NtpDuration,
}

impl PeerTimeSnapshot {
    pub fn root_distance(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
    ) -> NtpDuration {
        self.root_distance_without_time
            + (NtpInstant::abs_diff(local_clock_time, self.time) * frequency_tolerance)
    }

    pub fn from_timestate(timestate: &PeerTimeState) -> Self {
        Self {
            root_distance_without_time: timestate.root_distance_without_time(),
            statistics: timestate.statistics,
            time: timestate.time,
            stratum: timestate.last_packet.stratum(),
            leap_indicator: timestate.last_packet.leap(),
            root_delay: timestate.last_packet.root_delay(),
            root_dispersion: timestate.last_packet.root_dispersion(),
        }
    }

    pub fn accept_synchronization(
        &self,
        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
        distance_threshold: NtpDuration,
        system_poll: PollInterval,
    ) -> Result<(), AcceptSynchronizationError> {
        use AcceptSynchronizationError::*;

        let system_poll = system_poll.as_duration();

        // A stratum error occurs when the server has never been synchronized.
        if !self.leap_indicator.is_synchronized() {
            warn!("Rejected peer due to not being synchronized");
            return Err(Stratum);
        }

        //  A distance error occurs if the root distance exceeds the
        //  distance threshold plus an increment equal to one poll interval.
        let distance = self.root_distance(local_clock_time, frequency_tolerance);
        if distance > distance_threshold + (system_poll * frequency_tolerance) {
            debug!(
                ?distance,
                limit = debug(distance_threshold + (system_poll * frequency_tolerance)),
                "Peer rejected due to excessive distance"
            );

            return Err(Distance);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::time_types::PollIntervalLimits;

    use super::*;

    #[test]
    fn test_root_duration_sanity() {
        // Ensure root distance at least increases as it is supposed to
        // when changing the main measurement parameters

        let duration_1s = NtpDuration::from_fixed_int(1_0000_0000);
        let duration_2s = NtpDuration::from_fixed_int(2_0000_0000);

        // let timestamp_1s = NtpInstant::from_fixed_int(1_0000_0000);
        // let timestamp_2s = NtpInstant::from_fixed_int(2_0000_0000);

        let timestamp_0s = NtpInstant::now();
        let timestamp_1s = timestamp_0s + std::time::Duration::new(1, 0);
        let timestamp_2s = timestamp_0s + std::time::Duration::new(2, 0);

        let ft = FrequencyTolerance::ppm(15);

        let mut packet = NtpPacket::test();
        packet.set_root_delay(duration_1s);
        packet.set_root_dispersion(duration_1s);
        let reference = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };

        assert!(
            reference.root_distance(timestamp_1s, ft) < reference.root_distance(timestamp_2s, ft)
        );

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_2s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_2s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_0s)
        };
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        packet.set_root_delay(duration_2s);
        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        packet.set_root_delay(duration_1s);
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        packet.set_root_dispersion(duration_2s);
        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };
        packet.set_root_dispersion(duration_1s);
        assert!(reference.root_distance(timestamp_1s, ft) < sample.root_distance(timestamp_1s, ft));

        let sample = PeerTimeState {
            statistics: PeerStatistics {
                delay: duration_1s,
                dispersion: duration_1s,
                ..Default::default()
            },
            last_packet: packet.clone(),
            ..PeerTimeState::test_timestate(timestamp_1s)
        };

        assert_eq!(
            reference.root_distance(timestamp_1s, ft),
            sample.root_distance(timestamp_1s, ft)
        );
    }

    #[test]
    fn test_timesnapshot_accept_synchronization() {
        use AcceptSynchronizationError::*;

        let local_clock_time = NtpInstant::now();
        let mut timestate = PeerTimeState::test_timestate(local_clock_time);
        let ft = FrequencyTolerance::ppm(15);
        let dt = NtpDuration::ONE;
        let system_poll = PollIntervalLimits::default().min;

        macro_rules! accept {
            () => {{
                let snapshot = PeerTimeSnapshot::from_timestate(&timestate);
                snapshot.accept_synchronization(local_clock_time, ft, dt, system_poll)
            }};
        }

        timestate.last_packet.set_leap(NtpLeapIndicator::Unknown);
        assert_eq!(accept!(), Err(Stratum));

        timestate.last_packet.set_leap(NtpLeapIndicator::NoWarning);

        timestate.last_packet.set_root_dispersion(dt * 2);
        assert_eq!(accept!(), Err(Distance));
    }
}
