use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt::Debug, hash::Hash};

use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
use crate::source::{NtpSourceUpdate, SourceSnapshot};
use crate::{NtpTimestamp, OneWaySource, OneWaySourceUpdate};
use crate::{
    algorithm::{StateUpdate, TimeSyncController},
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
    /// Bloom filter that contains all currently used time sources
    #[serde(skip)]
    pub bloom_filter: BloomFilter,
    /// NTPv5 reference ID for this instance
    #[serde(skip)]
    pub server_id: ServerId,
}

impl SystemSnapshot {
    pub fn update_timedata(&mut self, timedata: TimeSnapshot, config: &SynchronizationConfig) {
        self.time_snapshot = timedata;
        self.accumulated_steps_threshold = config.accumulated_step_panic_threshold;
    }

    pub fn update_used_sources(&mut self, used_sources: impl Iterator<Item = SourceSnapshot>) {
        let mut used_sources = used_sources.peekable();
        if let Some(system_source_snapshot) = used_sources.peek() {
            let (stratum, source_id) = match system_source_snapshot {
                SourceSnapshot::Ntp(snapshot) => (snapshot.stratum, snapshot.source_id),
                SourceSnapshot::OneWay(snapshot) => (snapshot.stratum, snapshot.source_id),
            };

            self.stratum = stratum.saturating_add(1);
            self.reference_id = source_id;
        }

        self.bloom_filter = BloomFilter::new();
        for source in used_sources {
            if let SourceSnapshot::Ntp(source) = source {
                if let Some(bf) = &source.bloom_filter {
                    self.bloom_filter.add(bf);
                } else if let ProtocolVersion::V5 = source.protocol_version {
                    tracing::warn!("Using NTPv5 source without a bloom filter!");
                }
            }
        }
        self.bloom_filter.add_id(&self.server_id);
    }
}

impl Default for SystemSnapshot {
    fn default() -> Self {
        Self {
            stratum: 16,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: None,
            time_snapshot: TimeSnapshot::default(),
            bloom_filter: BloomFilter::new(),
            server_id: ServerId::default(),
        }
    }
}

pub struct SystemSourceUpdate<ControllerMessage> {
    pub message: ControllerMessage,
}

impl<ControllerMessage: Debug> std::fmt::Debug for SystemSourceUpdate<ControllerMessage> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemSourceUpdate")
            .field("message", &self.message)
            .finish()
    }
}

impl<ControllerMessage: Clone> Clone for SystemSourceUpdate<ControllerMessage> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SystemAction<ControllerMessage> {
    UpdateSources(SystemSourceUpdate<ControllerMessage>),
    SetTimer(Duration),
}

#[derive(Debug)]
pub struct SystemActionIterator<ControllerMessage> {
    iter: <Vec<SystemAction<ControllerMessage>> as IntoIterator>::IntoIter,
}

impl<ControllerMessage> Default for SystemActionIterator<ControllerMessage> {
    fn default() -> Self {
        Self {
            iter: vec![].into_iter(),
        }
    }
}

impl<ControllerMessage> From<Vec<SystemAction<ControllerMessage>>>
    for SystemActionIterator<ControllerMessage>
{
    fn from(value: Vec<SystemAction<ControllerMessage>>) -> Self {
        Self {
            iter: value.into_iter(),
        }
    }
}

impl<ControllerMessage> Iterator for SystemActionIterator<ControllerMessage> {
    type Item = SystemAction<ControllerMessage>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

macro_rules! actions {
    [$($action:expr),*] => {
        {
            SystemActionIterator::from(vec![$($action),*])
        }
    }
}

pub struct System<SourceId, Controller> {
    synchronization_config: SynchronizationConfig,
    system: SystemSnapshot,
    ip_list: Arc<[IpAddr]>,

    sources: HashMap<SourceId, Option<SourceSnapshot>>,

    controller: Controller,
    controller_took_control: bool,
}

impl<SourceId: Hash + Eq + Copy + Debug, Controller: TimeSyncController<SourceId = SourceId>>
    System<SourceId, Controller>
{
    pub fn new(
        clock: Controller::Clock,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Controller::AlgorithmConfig,
        ip_list: Arc<[IpAddr]>,
    ) -> Result<Self, <Controller::Clock as NtpClock>::Error> {
        // Setup system snapshot
        let mut system = SystemSnapshot {
            stratum: synchronization_config.local_stratum,
            ..Default::default()
        };

        if synchronization_config.local_stratum == 1 {
            // We are a stratum 1 server so mark our selves synchronized.
            system.time_snapshot.leap_indicator = NtpLeapIndicator::NoWarning;
            // Set the reference id for the system
            system.reference_id = synchronization_config.reference_id.to_reference_id();
        }

        Ok(System {
            synchronization_config,
            system,
            ip_list,
            sources: Default::default(),
            controller: Controller::new(clock, synchronization_config, algorithm_config)?,
            controller_took_control: false,
        })
    }

    pub fn system_snapshot(&self) -> SystemSnapshot {
        self.system
    }

    pub fn check_clock_access(&mut self) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        self.ensure_controller_control()
    }

    fn ensure_controller_control(&mut self) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        if !self.controller_took_control {
            self.controller.take_control()?;
            self.controller_took_control = true;
        }
        Ok(())
    }

    pub fn create_sock_source(
        &mut self,
        id: SourceId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
    ) -> Result<
        OneWaySource<Controller::OneWaySourceController>,
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller =
            self.controller
                .add_one_way_source(id, source_config, measurement_noise_estimate, None);
        self.sources.insert(id, None);
        Ok(OneWaySource::new(controller))
    }

    pub fn create_pps_source(
        &mut self,
        id: SourceId,
        source_config: SourceConfig,
        measurement_noise_estimate: f64,
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
            Some(period),
        );
        self.sources.insert(id, None);
        Ok(OneWaySource::new(controller))
    }

    pub fn create_ptp_source(
        &mut self,
        id: SourceId,
        source_config: SourceConfig,
        period: f64,
    ) -> Result<
        OneWaySource<Controller::OneWaySourceController>,
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller = self.controller.add_one_way_source(
            id,
            source_config,
            0.0, // Assume no noise from PTP sources for now
            Some(period),
        );
        self.sources.insert(id, None);
        Ok(OneWaySource::new(controller))
    }

    #[allow(clippy::type_complexity)]
    pub fn create_ntp_source(
        &mut self,
        id: SourceId,
        source_config: SourceConfig,
        source_addr: SocketAddr,
        protocol_version: ProtocolVersion,
        nts: Option<Box<SourceNtsData>>,
    ) -> Result<
        (
            NtpSource<Controller::NtpSourceController>,
            NtpSourceActionIterator<Controller::SourceMessage>,
        ),
        <Controller::Clock as NtpClock>::Error,
    > {
        self.ensure_controller_control()?;
        let controller = self.controller.add_source(id, source_config);
        self.sources.insert(id, None);
        Ok(NtpSource::new(
            source_addr,
            source_config,
            protocol_version,
            controller,
            nts,
        ))
    }

    pub fn handle_source_remove(
        &mut self,
        id: SourceId,
    ) -> Result<(), <Controller::Clock as NtpClock>::Error> {
        self.controller.remove_source(id);
        self.sources.remove(&id);
        Ok(())
    }

    pub fn handle_source_update(
        &mut self,
        id: SourceId,
        update: NtpSourceUpdate<Controller::SourceMessage>,
    ) -> Result<
        SystemActionIterator<Controller::ControllerMessage>,
        <Controller::Clock as NtpClock>::Error,
    > {
        let usable = update
            .snapshot
            .accept_synchronization(
                self.synchronization_config.local_stratum,
                self.ip_list.as_ref(),
                &self.system,
            )
            .is_ok();
        self.controller.source_update(id, usable);
        *self.sources.get_mut(&id).unwrap() = Some(SourceSnapshot::Ntp(update.snapshot));
        if let Some(message) = update.message {
            let update = self.controller.source_message(id, message);
            Ok(self.handle_algorithm_state_update(update))
        } else {
            Ok(actions!())
        }
    }

    pub fn handle_one_way_source_update(
        &mut self,
        id: SourceId,
        update: OneWaySourceUpdate<Controller::SourceMessage>,
    ) -> Result<
        SystemActionIterator<Controller::ControllerMessage>,
        <Controller::Clock as NtpClock>::Error,
    > {
        self.controller.source_update(id, true);
        *self.sources.get_mut(&id).unwrap() = Some(SourceSnapshot::OneWay(update.snapshot));
        if let Some(message) = update.message {
            let update = self.controller.source_message(id, message);
            Ok(self.handle_algorithm_state_update(update))
        } else {
            Ok(actions!())
        }
    }

    fn handle_algorithm_state_update(
        &mut self,
        update: StateUpdate<SourceId, Controller::ControllerMessage>,
    ) -> SystemActionIterator<Controller::ControllerMessage> {
        let mut actions = vec![];
        if let Some(ref used_sources) = update.used_sources {
            self.system
                .update_used_sources(used_sources.iter().map(|v| {
                    self.sources.get(v).and_then(|snapshot| *snapshot).expect(
                    "Critical error: Source used for synchronization that is not known to system",
                )
                }));
        }
        if let Some(time_snapshot) = update.time_snapshot {
            self.system
                .update_timedata(time_snapshot, &self.synchronization_config);
        }
        if let Some(timeout) = update.next_update {
            actions.push(SystemAction::SetTimer(timeout));
        }
        if let Some(message) = update.source_message {
            actions.push(SystemAction::UpdateSources(SystemSourceUpdate { message }))
        }
        actions.into()
    }

    pub fn handle_timer(&mut self) -> SystemActionIterator<Controller::ControllerMessage> {
        tracing::debug!("Timer expired");
        let update = self.controller.time_update();
        self.handle_algorithm_state_update(update)
    }

    pub fn update_ip_list(&mut self, ip_list: Arc<[IpAddr]>) {
        self.ip_list = ip_list;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::{NtpSourceSnapshot, time_types::PollIntervalLimits};

    use super::*;

    #[test]
    fn test_empty_source_update() {
        let mut system = SystemSnapshot::default();

        // Should do nothing
        system.update_used_sources(std::iter::empty());

        assert_eq!(system.stratum, 16);
        assert_eq!(system.reference_id, ReferenceId::NONE);
    }

    #[test]
    fn test_source_update() {
        let mut system = SystemSnapshot::default();

        system.update_used_sources(
            vec![
                SourceSnapshot::Ntp(NtpSourceSnapshot {
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_DENY,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 2,
                    reference_id: ReferenceId::NONE,
                    protocol_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
                    bloom_filter: None,
                }),
                SourceSnapshot::Ntp(NtpSourceSnapshot {
                    source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    source_id: ReferenceId::KISS_RATE,
                    poll_interval: PollIntervalLimits::default().max,
                    reach: Default::default(),
                    stratum: 3,
                    reference_id: ReferenceId::NONE,
                    protocol_version: ProtocolVersion::v4_upgrading_to_v5_with_default_tries(),
                    bloom_filter: None,
                }),
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
