use serde::{Deserialize, Serialize};
use statime_base::{LeapStatus, LinkId, TimeSnapshot};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

use crate::packet::v5::server_reference_id::{BloomFilter, ServerId};
use crate::source::SourceSnapshot;
use crate::{ClockId, KeySet, NtpSourceSnapshot, Server, ServerConfig, SourceController};
use crate::{
    config::{SourceConfig, SynchronizationConfig},
    identifiers::ReferenceId,
    source::{NtpSource, NtpSourceActionIterator, ProtocolVersion, SourceNtsData},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct SystemSnapshot {
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
    Csptp,
}

#[derive(Default, Copy, Clone)]
pub struct NtpServerInfo {
    pub time_snapshot: TimeSnapshot,
    pub ntp_snapshot: NtpSnapshot,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct NtpSourceInfo {
    pub(crate) ip_list: Arc<[IpAddr]>,
    pub(crate) server_id: ServerId,
    pub(crate) local_stratum: u8,
}

pub struct NtpManager {
    synchronization_config: SynchronizationConfig,
    server_id: ServerId,
    source_snapshots: Arc<Mutex<HashMap<LinkId, NtpSourceSnapshot>>>,

    server_info: Arc<RwLock<NtpServerInfo>>,
    source_info: Arc<RwLock<NtpSourceInfo>>,
}

impl NtpManager {
    pub fn new(synchronization_config: SynchronizationConfig, ip_list: Arc<[IpAddr]>) -> Self {
        let server_id = ServerId::default();
        let source_info = NtpSourceInfo {
            ip_list,
            server_id,
            local_stratum: synchronization_config.local_stratum,
        };
        let mut server_info = NtpServerInfo {
            time_snapshot: TimeSnapshot::default(),
            ntp_snapshot: NtpSnapshot::default(),
        };
        if synchronization_config.local_stratum == 1 {
            // We are a stratum 1 server so mark our selves synchronized.
            // FIXME: Reconside rwhether we should do this as it signals knowledge
            // of the leap status.
            server_info.time_snapshot.leap_indicator = Some(LeapStatus::None);
            // Set the reference id for the system
            server_info.ntp_snapshot.reference_id =
                synchronization_config.reference_id.to_reference_id();
        }
        Self {
            synchronization_config,
            server_id,
            source_snapshots: Arc::new(Mutex::new(HashMap::new())),

            server_info: Arc::new(RwLock::new(server_info)),
            source_info: Arc::new(RwLock::new(source_info)),
        }
    }

    pub fn new_server<C>(&self, config: ServerConfig, clock: C, keyset: Arc<KeySet>) -> Server<C> {
        Server::new_internal(config, clock, self.server_info.clone(), keyset)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "FIXME: rework ntp source and manager to use new algorithm."
    )]
    pub fn new_source<Controller: SourceController>(
        &self,
        source_addr: SocketAddr,
        source_config: SourceConfig,
        protocol_version: ProtocolVersion,
        controller: Controller,
        nts: Option<Box<SourceNtsData>>,
        id: ClockId,
        link_id: LinkId,
    ) -> (NtpSource<Controller>, NtpSourceActionIterator) {
        NtpSource::new(
            source_addr,
            source_config,
            protocol_version,
            controller,
            nts,
            id,
            link_id,
            self.source_info.clone(),
            self.source_snapshots.clone(),
        )
    }

    pub fn update_ip_list(&self, ip_list: Arc<[IpAddr]>) {
        self.source_info.write().unwrap().ip_list = ip_list;
    }

    pub fn update_used_sources(
        &self,
        sources: impl Iterator<Item = (LinkId, SourceType)>,
    ) -> NtpSnapshot {
        let source_snapshots = self.source_snapshots.lock().unwrap();
        let sources: Option<Vec<_>> = sources
            .map(|(id, sourcetype)| match sourcetype {
                SourceType::Pps => Some(SourceSnapshot::External {
                    stratum: 0,
                    source_id: ReferenceId::PPS,
                }),
                SourceType::Sock => Some(SourceSnapshot::External {
                    stratum: 0,
                    source_id: ReferenceId::SOCK,
                }),
                SourceType::Ntp => source_snapshots.get(&id).copied().map(SourceSnapshot::Ntp),
                SourceType::Csptp => Some(SourceSnapshot::External {
                    stratum: 0,
                    source_id: ReferenceId::CSPTP,
                }),
            })
            .collect();
        drop(source_snapshots);

        if let Some(sources) = sources {
            let snapshot = NtpSnapshot::from_used_sources(
                self.synchronization_config.local_stratum,
                self.server_id,
                sources.into_iter(),
            );

            self.server_info.write().unwrap().ntp_snapshot = snapshot;

            snapshot
        } else {
            self.server_info.read().unwrap().ntp_snapshot
        }
    }

    pub fn observe(&self) -> NtpSnapshot {
        self.server_info.read().unwrap().ntp_snapshot
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
