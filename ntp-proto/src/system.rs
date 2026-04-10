use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
use crate::source::{NtpSourceUpdate, SourceSnapshot};
use crate::{
    ClockId, KeySet, NtpSourceSnapshot, NtpTimestamp, OneWaySource, Server, ServerConfig,
    SourceController,
};
use crate::{
    algorithm::TimeSyncController,
    clock::NtpClock,
    config::{SourceConfig, SynchronizationConfig},
    identifiers::ReferenceId,
    packet::NtpLeapIndicator,
    source::{NtpSource, NtpSourceActionIterator, ProtocolVersion, SourceNtsData},
    time_types::NtpDuration,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct TimeSnapshot {
    /// Precision of the local clock
    pub precision: NtpDuration,
    /// Current root delay
    pub root_delay: NtpDuration,
    /// t=0 for root variance calculation
    pub root_variance_base_time: NtpTimestamp,
    /// Constant contribution for root variance
    pub root_variance_base: f64,
    /// Linear (*t) contribution for root variance
    pub root_variance_linear: f64,
    /// Quadratic (*t*t) contribution for root variance
    pub root_variance_quadratic: f64,
    /// Cubic (*t*t*t) contribution for root variance
    pub root_variance_cubic: f64,
    /// Current leap indicator state
    pub leap_indicator: NtpLeapIndicator,
    /// Total amount that the clock has stepped
    pub accumulated_steps: NtpDuration,
}

impl TimeSnapshot {
    pub fn root_dispersion(&self, now: NtpTimestamp) -> NtpDuration {
        let t = (now - self.root_variance_base_time).to_seconds();
        // Note: dispersion is the standard deviation, so we need a sqrt here.
        NtpDuration::from_seconds(
            (self.root_variance_base
                + t * self.root_variance_linear
                + t.powi(2) * self.root_variance_quadratic
                + t.powi(3) * self.root_variance_cubic)
                .sqrt(),
        )
    }
}

impl Default for TimeSnapshot {
    fn default() -> Self {
        Self {
            precision: NtpDuration::from_exponent(-18),
            root_delay: NtpDuration::ZERO,
            root_variance_base_time: NtpTimestamp::default(),
            root_variance_base: 0.0,
            root_variance_linear: 0.0,
            root_variance_quadratic: 0.0,
            root_variance_cubic: 0.0,
            leap_indicator: NtpLeapIndicator::Unknown,
            accumulated_steps: NtpDuration::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct SystemSnapshot {
    /// Crossing this amount of stepping will cause a Panic
    pub accumulated_steps_threshold: Option<NtpDuration>,
    /// Timekeeping data
    #[serde(flatten)]
    pub time_snapshot: TimeSnapshot,
    /// NTP specific data
    #[serde(flatten)]
    pub ntp_snapshot: NtpSnapshot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NtpSnapshot {
    /// Log of the precision of the local clock
    pub stratum: u8,
    /// Reference ID of current primary time source
    pub reference_id: ReferenceId,
    /// Bloom filter that contains all currently used time sources
    #[serde(skip)]
    pub bloom_filter: BloomFilter,
}

impl NtpSnapshot {
    pub fn from_used_sources(
        local_stratum: u8,
        server_id: ServerId,
        used_sources: impl Iterator<Item = SourceSnapshot>,
    ) -> Self {
        let mut stratum = local_stratum;
        let mut reference_id = ReferenceId::NONE;

        let mut used_sources = used_sources.peekable();
        if let Some(system_source_snapshot) = used_sources.peek() {
            let (source_stratum, source_id) = match system_source_snapshot {
                SourceSnapshot::Ntp(snapshot) => (snapshot.stratum, snapshot.source_id),
                SourceSnapshot::External { stratum, source_id } => (*stratum, *source_id),
            };

            stratum = source_stratum.saturating_add(1);
            reference_id = source_id;
        }

        let mut bloom_filter = BloomFilter::new();
        for source in used_sources {
            if let SourceSnapshot::Ntp(source) = source {
                if let Some(bf) = &source.bloom_filter {
                    bloom_filter.add(bf);
                } else if let ProtocolVersion::V5 = source.protocol_version {
                    tracing::warn!("Using NTPv5 source without a bloom filter!");
                }
            }
        }
        bloom_filter.add_id(&server_id);

        Self {
            stratum,
            reference_id,
            bloom_filter,
        }
    }
}

impl Default for NtpSnapshot {
    fn default() -> Self {
        Self {
            stratum: 16,
            reference_id: ReferenceId::NONE,
            bloom_filter: BloomFilter::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    Pps,
    Sock,
    Ntp,
}

pub struct System<Controller> {
    synchronization_config: SynchronizationConfig,
    system: Mutex<SystemSnapshot>,
    ntp_manager: NtpManager,

    sources: Mutex<HashMap<ClockId, SourceType>>,

    controller: Controller,
    controller_took_control: Mutex<bool>,
}

impl<Controller: TimeSyncController> System<Controller> {
    pub fn new(
        clock: Controller::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Controller::AlgorithmConfig,
        ip_list: Arc<[IpAddr]>,
    ) -> Result<Self, <Controller::Clock as NtpClock>::Error> {
        // Setup system snapshot
        let mut system = SystemSnapshot {
            ntp_snapshot: NtpSnapshot {
                stratum: synchronization_config.local_stratum,
                ..Default::default()
            },
            ..Default::default()
        };

        if synchronization_config.local_stratum == 1 {
            // We are a stratum 1 server so mark our selves synchronized.
            system.time_snapshot.leap_indicator = NtpLeapIndicator::NoWarning;
            // Set the reference id for the system
            system.ntp_snapshot.reference_id =
                synchronization_config.reference_id.to_reference_id();
        }

        Ok(System {
            synchronization_config,
            ntp_manager: NtpManager::new(synchronization_config, ip_list),
            system: Mutex::new(system),
            sources: Mutex::new(HashMap::new()),
            controller: Controller::new(clock, synchronization_config, algorithm_config)?,
            controller_took_control: Mutex::new(false),
        })
    }

    pub fn new_ntp_server<C>(
        &self,
        config: ServerConfig,
        clock: C,
        keyset: Arc<KeySet>,
    ) -> Server<C> {
        self.ntp_manager.new_server(config, clock, keyset)
    }

    pub fn system_snapshot(&self) -> SystemSnapshot {
        *self.system.lock().unwrap()
    }

    pub fn check_clock_access(&self) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        self.ensure_controller_control()
    }

    fn ensure_controller_control(&self) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        // FIXME: the take control pattern needs to go. Until that time this is not ideal but will do.
        let mut controller_took_control = self.controller_took_control.lock().unwrap();
        if !*controller_took_control {
            self.controller.take_control()?;
            *controller_took_control = true;
        }
        Ok(())
    }

    pub fn create_sock_source(
        &self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        measurement_accuracy_estimate: f64,
    ) -> Result<
        OneWaySource<Controller::OneWaySourceController>,
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller = self.controller.add_one_way_source(
            id,
            source_config,
            measurement_noise_estimate,
            measurement_accuracy_estimate,
            None,
        );
        self.sources.lock().unwrap().insert(id, SourceType::Sock);
        self.controller.source_update(id, true);
        Ok(OneWaySource::new(controller))
    }

    pub fn create_pps_source(
        &self,
        id: ClockId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
        measurement_accuracy_estimate: f64,
        period: f64,
    ) -> Result<
        OneWaySource<Controller::OneWaySourceController>,
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller = self.controller.add_one_way_source(
            id,
            source_config,
            measurement_noise_estimate,
            measurement_accuracy_estimate,
            Some(period),
        );
        self.sources.lock().unwrap().insert(id, SourceType::Pps);
        self.controller.source_update(id, true);
        Ok(OneWaySource::new(controller))
    }

    #[expect(clippy::type_complexity)]
    pub fn create_ntp_source(
        &self,
        id: ClockId,
        source_config: SourceConfig,
        source_addr: SocketAddr,
        protocol_version: ProtocolVersion,
        nts: Option<Box<SourceNtsData>>,
    ) -> Result<
        (
            NtpSource<Controller::NtpSourceController>,
            NtpSourceActionIterator,
        ),
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller = self.controller.add_source(id, source_config);
        self.sources.lock().unwrap().insert(id, SourceType::Ntp);
        Ok(self.ntp_manager.new_source(
            source_addr,
            source_config,
            protocol_version,
            controller,
            nts,
            id,
        ))
    }

    pub fn handle_source_remove(
        &self,
        id: ClockId,
    ) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        self.controller.remove_source(id);
        self.sources.lock().unwrap().remove(&id);
        Ok(())
    }

    pub fn handle_source_update(&self, id: ClockId, update: &NtpSourceUpdate) {
        let (usability_change_id, usability_change_usable) =
            self.ntp_manager.handle_source_update(id, update);
        self.controller
            .source_update(usability_change_id, usability_change_usable);
    }

    pub fn update_ip_list(&self, ip_list: Arc<[IpAddr]>) {
        self.ntp_manager.update_ip_list(ip_list);
    }

    pub fn run(self: Arc<Self>) -> impl Future<Output = ()> + 'static {
        let this = self.clone();
        let update_pusher = async move {
            loop {
                // Scope here is needed to keep this future sync and send.
                {
                    let (time_snapshot, used_sources) = this.controller.synchronization_state();
                    let sources = this.sources.lock().unwrap();
                    this.ntp_manager.update_time_snapshot(time_snapshot);
                    let ntp_snapshot =
                        this.ntp_manager
                            .update_used_sources(used_sources.iter().map(|id| {
                                (
                                    *id,
                                    *sources.get(id).expect(
                                        "Critical error: Unknown source used for synchronization",
                                    ),
                                )
                            }));

                    *this.system.lock().unwrap() = SystemSnapshot {
                        ntp_snapshot,
                        time_snapshot,
                        accumulated_steps_threshold: this
                            .synchronization_config
                            .accumulated_step_panic_threshold,
                    };
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        };

        let controller_run = async move { self.controller.run().await };

        async move {
            tokio::join!(update_pusher, controller_run);
        }
    }
}

#[derive(Default, Copy, Clone)]
pub struct NtpServerInfo {
    pub time_snapshot: TimeSnapshot,
    pub ntp_snapshot: NtpSnapshot,
}

pub struct NtpManager {
    synchronization_config: SynchronizationConfig,
    server_id: ServerId,
    source_snapshots: Mutex<HashMap<ClockId, NtpSourceSnapshot>>,
    ip_list: Mutex<Arc<[IpAddr]>>,

    server_info: Arc<RwLock<NtpServerInfo>>,
}

impl NtpManager {
    pub fn new(synchronization_config: SynchronizationConfig, ip_list: Arc<[IpAddr]>) -> Self {
        Self {
            synchronization_config,
            server_id: ServerId::default(),
            source_snapshots: Mutex::new(HashMap::new()),
            ip_list: Mutex::new(ip_list),

            server_info: Arc::default(),
        }
    }

    pub fn new_server<C>(&self, config: ServerConfig, clock: C, keyset: Arc<KeySet>) -> Server<C> {
        Server::new_internal(config, clock, self.server_info.clone(), keyset)
    }

    #[expect(clippy::unused_self)]
    pub fn new_source<Controller: SourceController>(
        &self,
        source_addr: SocketAddr,
        source_config: SourceConfig,
        protocol_version: ProtocolVersion,
        controller: Controller,
        nts: Option<Box<SourceNtsData>>,
        id: ClockId,
    ) -> (NtpSource<Controller>, NtpSourceActionIterator) {
        NtpSource::new(
            source_addr,
            source_config,
            protocol_version,
            controller,
            nts,
            id,
        )
    }

    pub fn update_ip_list(&self, ip_list: Arc<[IpAddr]>) {
        *self.ip_list.lock().unwrap() = ip_list;
    }

    pub fn handle_source_update(&self, id: ClockId, update: &NtpSourceUpdate) -> (ClockId, bool) {
        let ip_list = self.ip_list.lock().unwrap().clone();
        let usable = update
            .snapshot
            .accept_synchronization(
                self.synchronization_config.local_stratum,
                ip_list.as_ref(),
                self.server_id,
            )
            .is_ok();
        self.source_snapshots
            .lock()
            .unwrap()
            .insert(id, update.snapshot);
        (id, usable)
    }

    pub fn update_used_sources(
        &self,
        sources: impl Iterator<Item = (ClockId, SourceType)>,
    ) -> NtpSnapshot {
        let source_snapshots = self.source_snapshots.lock().unwrap();
        let snapshot = NtpSnapshot::from_used_sources(
            self.synchronization_config.local_stratum,
            self.server_id,
            sources.map(|(id, sourcetype)| match sourcetype {
                SourceType::Pps => SourceSnapshot::External { stratum: 0, source_id: ReferenceId::PPS },
                SourceType::Sock => SourceSnapshot::External { stratum: 0, source_id: ReferenceId::SOCK },
                SourceType::Ntp => SourceSnapshot::Ntp(*source_snapshots.get(&id).expect(
                    "Critical error: NTP source used for synchronization never produced source updates",
                )),
            }),
        );
        drop(source_snapshots);

        self.server_info.write().unwrap().ntp_snapshot = snapshot;

        snapshot
    }

    pub fn update_time_snapshot(&self, time_snapshot: TimeSnapshot) {
        self.server_info.write().unwrap().time_snapshot = time_snapshot;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::{NtpSourceSnapshot, Reach, time_types::PollIntervalLimits};

    use super::*;

    #[test]
    fn test_empty_source_update() {
        // Should do nothing
        let ntps = NtpSnapshot::from_used_sources(16, ServerId::default(), std::iter::empty());

        assert_eq!(ntps.stratum, 16);
        assert_eq!(ntps.reference_id, ReferenceId::NONE);
    }

    #[test]
    fn test_source_update() {
        let ntps = NtpSnapshot::from_used_sources(
            16,
            ServerId::default(),
            vec![
                SourceSnapshot::Ntp(NtpSourceSnapshot {
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_DENY,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Reach::never(),
                    stratum: 2,
                    reference_id: ReferenceId::NONE,
                    protocol_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
                    bloom_filter: None,
                }),
                SourceSnapshot::Ntp(NtpSourceSnapshot {
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_RATE,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Reach::never(),
                    stratum: 3,
                    reference_id: ReferenceId::NONE,
                    protocol_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
                    bloom_filter: None,
                }),
            ]
            .into_iter(),
        );

        assert_eq!(ntps.stratum, 3);
        assert_eq!(ntps.reference_id, ReferenceId::KISS_DENY);
    }
}
