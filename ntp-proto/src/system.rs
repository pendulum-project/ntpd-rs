use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt::Debug, hash::Hash};

#[cfg(feature = "ntpv5")]
use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
use crate::peer::PeerUpdate;
#[cfg(feature = "ntpv5")]
use crate::peer::ProtocolVersion;
use crate::{
    algorithm::{KalmanClockController, ObservablePeerTimedata, StateUpdate, TimeSyncController},
    clock::NtpClock,
    config::{SourceDefaultsConfig, SynchronizationConfig},
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

    #[cfg(feature = "ntpv5")]
    /// Bloom filter that contains all currently used time sources
    #[serde(skip)]
    pub bloom_filter: BloomFilter,
    #[cfg(feature = "ntpv5")]
    /// NTPv5 reference ID for this instance
    #[serde(skip)]
    pub server_id: ServerId,
}

impl SystemSnapshot {
    pub fn update_timedata(&mut self, timedata: TimeSnapshot, config: &SynchronizationConfig) {
        self.time_snapshot = timedata;
        self.accumulated_steps_threshold = config.accumulated_step_panic_threshold;
    }

    pub fn update_used_peers(&mut self, used_peers: impl Iterator<Item = PeerSnapshot>) {
        let mut used_peers = used_peers.peekable();
        if let Some(system_peer_snapshot) = used_peers.peek() {
            self.stratum = system_peer_snapshot.stratum.saturating_add(1);
            self.reference_id = system_peer_snapshot.source_id;
        }

        #[cfg(feature = "ntpv5")]
        {
            self.bloom_filter = BloomFilter::new();
            for peer in used_peers {
                if let Some(bf) = &peer.bloom_filter {
                    self.bloom_filter.add(bf);
                } else if let ProtocolVersion::V5 = peer.protocol_version {
                    tracing::warn!("Using NTPv5 peer without a bloom filter!");
                }
            }
            self.bloom_filter.add_id(&self.server_id);
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
            #[cfg(feature = "ntpv5")]
            bloom_filter: BloomFilter::new(),
            #[cfg(feature = "ntpv5")]
            server_id: ServerId::new(&mut rand::thread_rng()),
        }
    }
}

pub struct System<C: NtpClock, PeerId: Hash + Eq + Copy + Debug> {
    synchronization_config: SynchronizationConfig,
    peer_defaults_config: SourceDefaultsConfig,
    system: SystemSnapshot,
    ip_list: Arc<[IpAddr]>,

    peers: HashMap<PeerId, Option<PeerSnapshot>>,

    clock: C,
    controller: Option<KalmanClockController<C, PeerId>>,
}

impl<C: NtpClock, PeerId: Hash + Eq + Copy + Debug> System<C, PeerId> {
    pub fn new(
        clock: C,
        synchronization_config: SynchronizationConfig,
        peer_defaults_config: SourceDefaultsConfig,
        ip_list: Arc<[IpAddr]>,
    ) -> Self {
        // Setup system snapshot
        let mut system = SystemSnapshot {
            stratum: synchronization_config.local_stratum,
            ..Default::default()
        };

        if synchronization_config.local_stratum == 1 {
            // We are a stratum 1 server so mark our selves synchronized.
            system.time_snapshot.leap_indicator = NtpLeapIndicator::NoWarning;
        }

        System {
            synchronization_config,
            peer_defaults_config,
            system,
            ip_list,
            peers: Default::default(),
            clock,
            controller: None,
        }
    }

    pub fn system_snapshot(&self) -> SystemSnapshot {
        self.system
    }

    fn clock_controller(&mut self) -> Result<&mut KalmanClockController<C, PeerId>, C::Error> {
        let controller = match self.controller.take() {
            Some(controller) => controller,
            None => KalmanClockController::new(
                self.clock.clone(),
                self.synchronization_config,
                self.peer_defaults_config,
                self.synchronization_config.algorithm,
            )?,
        };
        Ok(self.controller.insert(controller))
    }

    pub fn handle_peer_create(&mut self, id: PeerId) -> Result<(), C::Error> {
        self.clock_controller()?.peer_add(id);
        self.peers.insert(id, None);
        Ok(())
    }

    pub fn handle_peer_remove(&mut self, id: PeerId) -> Result<(), C::Error> {
        self.clock_controller()?.peer_remove(id);
        self.peers.remove(&id);
        Ok(())
    }

    pub fn handle_peer_update(
        &mut self,
        id: PeerId,
        update: PeerUpdate,
    ) -> Result<Option<Duration>, C::Error> {
        let usable = update
            .snapshot
            .accept_synchronization(
                self.synchronization_config.local_stratum,
                self.ip_list.as_ref(),
                &self.system,
            )
            .is_ok();
        self.clock_controller()?.peer_update(id, usable);
        *self.peers.get_mut(&id).unwrap() = Some(update.snapshot);
        if let Some(measurement) = update.measurement {
            let update = self.clock_controller()?.peer_measurement(id, measurement);
            Ok(self.handle_algorithm_state_update(update))
        } else {
            Ok(None)
        }
    }

    fn handle_algorithm_state_update(&mut self, update: StateUpdate<PeerId>) -> Option<Duration> {
        if let Some(ref used_peers) = update.used_peers {
            self.system.update_used_peers(used_peers.iter().map(|v| {
                self.peers.get(v).and_then(|snapshot| *snapshot).expect(
                    "Critical error: Peer used for synchronization that is not known to system",
                )
            }));
        }
        if let Some(time_snapshot) = update.time_snapshot {
            self.system
                .update_timedata(time_snapshot, &self.synchronization_config);
        }
        update.next_update
    }

    pub fn handle_timer(&mut self) -> Option<Duration> {
        tracing::debug!("Timer expired");
        // note: local needed for borrow checker
        if let Some(controller) = self.controller.as_mut() {
            let update = controller.time_update();
            self.handle_algorithm_state_update(update)
        } else {
            None
        }
    }

    pub fn observe_peer(&self, id: PeerId) -> Option<(PeerSnapshot, ObservablePeerTimedata)> {
        if let Some(ref controller) = self.controller {
            self.peers
                .get(&id)
                .copied()
                .flatten()
                .and_then(|v| controller.peer_snapshot(id).map(|s| (v, s)))
        } else {
            None
        }
    }

    pub fn update_ip_list(&mut self, ip_list: Arc<[IpAddr]>) {
        self.ip_list = ip_list;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

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
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_DENY,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 2,
                    reference_id: ReferenceId::NONE,
                    protocol_version: Default::default(),
                    #[cfg(feature = "ntpv5")]
                    bloom_filter: None,
                },
                PeerSnapshot {
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_RATE,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 3,
                    reference_id: ReferenceId::NONE,
                    protocol_version: Default::default(),
                    #[cfg(feature = "ntpv5")]
                    bloom_filter: None,
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
