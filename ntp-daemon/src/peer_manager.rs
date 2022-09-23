use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::{
    config::{PeerConfig, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    observer::ObservablePeerState,
    peer::{MsgForSystem, PeerChannels, PeerTask, ResetEpoch},
    server::ServerTask,
};
use ntp_proto::{NtpClock, PeerSnapshot};
use tokio::{net::lookup_host, task::JoinHandle};
use tracing::warn;

const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub enum PeerStatus {
    /// We are waiting for the first snapshot from this peer _in the current reset epoch_.
    /// This state is the initial state for all peers (when the system is spawned), and also
    /// entered when the system performs a clock jump and forces all peers to reset, or when a peer
    /// indicates that it is no longer fit for synchronization (e.g. root distance became too big)
    ///
    /// A peer can leave this state by either becoming demobilized, or by sending a snapshot that
    /// is within the system's current reset epoch.
    NoMeasurement,
    /// This peer has sent snapshots taken in the current reset epoch. We store the most recent one
    Measurement(PeerSnapshot),
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PeerIndex {
    index: usize,
}

impl PeerIndex {
    #[cfg(test)]
    pub fn from_inner(index: usize) -> Self {
        PeerIndex { index }
    }
}

#[derive(Debug, Default)]
struct PeerIndexIssuer {
    next: usize,
}

impl PeerIndexIssuer {
    fn get(&mut self) -> PeerIndex {
        let index = self.next;
        self.next += 1;
        PeerIndex { index }
    }
}

#[derive(Debug)]
struct PeerData {
    status: PeerStatus,
    config: PeerConfig,
    socket_address: std::net::SocketAddr,
}

#[derive(Debug, Default)]
struct PoolState {
    /// Currently active peers taken from this pool
    active: Vec<std::net::SocketAddr>,

    /// Valid socket addresses in the pool, that are not currently active peers
    backups: Vec<std::net::SocketAddr>,
}

impl PoolState {
    /// Find additional peers from the pool
    ///
    /// - will do a DNS resolve if there are insufficient `backups`
    /// - will never add more than `max_peers` active peers from the pool
    async fn find_additional(&mut self, address: &str, max_peers: usize) -> Vec<SocketAddr> {
        if self.backups.len() < (max_peers - self.active.len()) {
            // there are not enough cached peers; try and get more with DNS resolve
            self.backups = socket_addresses(address)
                .await
                .filter(|addr| !self.active.contains(addr))
                .collect();
        }

        let additional = max_peers
            .saturating_sub(self.active.len())
            .min(self.backups.len());

        // bit nasty, but we actually want to split the first part off, not the last part
        let mut new_active = self.backups.split_off(additional);
        std::mem::swap(&mut new_active, &mut self.backups);

        self.active.extend(new_active.iter().copied());

        new_active
    }
}

/// Get available socket addresses for a host
///
/// Will retry until the iterator contains at least one socket address
async fn socket_addresses(address: &str) -> impl Iterator<Item = std::net::SocketAddr> + '_ {
    loop {
        match lookup_host(address).await {
            Ok(addresses) => {
                let mut it = addresses.peekable();

                match it.peek() {
                    None => {
                        warn!("Could not resolve peer address, retrying");
                        tokio::time::sleep(NETWORK_WAIT_PERIOD).await
                    }
                    Some(_) => break it,
                }
            }
            Err(e) => {
                warn!(error = ?e, "error while resolving peer address, retrying");
                tokio::time::sleep(NETWORK_WAIT_PERIOD).await
            }
        }
    }
}

#[derive(Debug)]
pub struct Peers<C: NtpClock> {
    peers: HashMap<PeerIndex, PeerData>,
    pools: HashMap<String, PoolState>,
    servers: Vec<Arc<ServerConfig>>,
    indexer: PeerIndexIssuer,

    channels: PeerChannels,
    clock: C,
}

impl<C: NtpClock> Peers<C> {
    pub fn new(channels: PeerChannels, clock: C) -> Self {
        Peers {
            peers: Default::default(),
            servers: Default::default(),
            indexer: Default::default(),
            pools: HashMap::new(),
            channels,
            clock,
        }
    }

    fn spawn_peer_task(&mut self, addr: SocketAddr, config: PeerConfig) -> JoinHandle<()> {
        let index = self.indexer.get();

        self.peers.insert(
            index,
            PeerData {
                status: PeerStatus::NoMeasurement,
                config,
                socket_address: addr,
            },
        );

        PeerTask::spawn(
            index,
            addr,
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
            self.channels.clone(),
        )
    }

    async fn add_peer_internal(&mut self, config: PeerConfig) -> Vec<JoinHandle<()>> {
        let new_active = match &config {
            PeerConfig::Standard(StandardPeerConfig { addr, .. }) => {
                // unwrap is safe because of the peek() in `socket_addresses`
                let address = socket_addresses(addr).await.next().unwrap();

                vec![address]
            }
            PeerConfig::Pool(PoolPeerConfig { addr, max_peers }) => {
                let pool_status = self.pools.entry(addr.to_string()).or_default();
                pool_status.find_additional(addr, *max_peers).await
            }
        };

        new_active
            .into_iter()
            .map(|addr| self.spawn_peer_task(addr, config.clone()))
            .collect()
    }

    /// Remove a peer from the data structure. This does not actually stop the peer task; it is
    /// assumed that the peer task is already stopped (e.g. because it crashed)
    fn remove_peer(&mut self, index: &PeerIndex) -> Option<PeerData> {
        self.peers.remove(index).map(|peer_data| {
            if let PeerConfig::Pool(PoolPeerConfig { addr, .. }) = &peer_data.config {
                if let Some(pool_status) = self.pools.get_mut(addr) {
                    pool_status
                        .active
                        .retain(|a| *a != peer_data.socket_address);
                }
            }

            peer_data
        })
    }

    pub async fn add_peer(&mut self, config: PeerConfig) -> Vec<JoinHandle<()>> {
        self.add_peer_internal(config).await
    }

    fn add_server_internal(&mut self, config: Arc<ServerConfig>) -> JoinHandle<()> {
        let addr = config.addr;
        self.servers.push(config);
        ServerTask::spawn(
            addr,
            self.channels.system_snapshots.clone(),
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
        )
    }

    pub async fn add_server(&mut self, config: ServerConfig) -> JoinHandle<()> {
        self.add_server_internal(Arc::new(config))
    }

    #[cfg(test)]
    pub fn from_statuslist(data: &[PeerStatus], raw_configs: &[PeerConfig], clock: C) -> Self {
        assert_eq!(data.len(), raw_configs.len());

        let mut peers = HashMap::new();
        let mut indexer = PeerIndexIssuer::default();

        for (i, status) in data.iter().enumerate() {
            let index = indexer.get();
            peers.insert(
                index,
                PeerData {
                    status: status.to_owned(),
                    config: raw_configs[i].clone(),
                    socket_address: "127.0.0.1:8000".parse().unwrap(),
                },
            );
        }

        Self {
            peers,
            pools: HashMap::default(),
            servers: vec![],
            indexer,
            channels: PeerChannels::test(),
            clock,
        }
    }

    pub fn size(&self) -> usize {
        self.peers.len()
    }

    pub fn observe(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(_, data)| match data.status {
            PeerStatus::NoMeasurement => ObservablePeerState::Nothing,
            PeerStatus::Measurement(snapshot) => ObservablePeerState::Observable {
                statistics: snapshot.statistics,
                reachability: snapshot.reach,
                uptime: snapshot.time.elapsed(),
                poll_interval: snapshot.poll_interval.as_system_duration(),
                peer_id: snapshot.peer_id,
                address: match &data.config {
                    PeerConfig::Standard(StandardPeerConfig { addr, .. }) => addr.to_string(),
                    PeerConfig::Pool(PoolPeerConfig { addr, .. }) => addr.to_string(),
                },
            },
        })
    }

    pub fn valid_snapshots(&self) -> impl Iterator<Item = PeerSnapshot> + '_ {
        self.peers.iter().filter_map(|(_, data)| match data.status {
            PeerStatus::NoMeasurement => None,
            PeerStatus::Measurement(snapshot) => Some(snapshot),
        })
    }

    pub async fn update(&mut self, msg: MsgForSystem, current_reset_epoch: ResetEpoch) {
        match msg {
            MsgForSystem::MustDemobilize(index) => {
                self.peers.remove(&index);
            }
            MsgForSystem::NewMeasurement(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                }
            }
            MsgForSystem::UpdatedSnapshot(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                }
            }
            MsgForSystem::NetworkIssue(index) => {
                // Restart the peer reusing its configuration.
                let config = self.remove_peer(&index).unwrap().config;
                self.add_peer_internal(config).await;
            }
        }
    }

    pub fn reset_all(&mut self) {
        for (_, data) in self.peers.iter_mut() {
            data.status = PeerStatus::NoMeasurement;
        }
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::{
        peer_snapshot, NtpDuration, NtpInstant, NtpLeapIndicator, NtpTimestamp, PeerStatistics,
        PollInterval,
    };

    use crate::config::StandardPeerConfig;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn set_freq(&self, _freq: f64) -> Result<(), Self::Error> {
            Ok(())
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_clock(
            &self,
            _offset: NtpDuration,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
            _poll_interval: PollInterval,
            _leap_status: NtpLeapIndicator,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_peers() {
        let base = NtpInstant::now();
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();
        let mut peers = Peers::from_statuslist(
            &[PeerStatus::NoMeasurement; 4],
            &(0..4)
                .map(|i| {
                    PeerConfig::Standard(StandardPeerConfig {
                        addr: format!("127.0.0.{i}:123"),
                    })
                })
                .collect::<Vec<_>>(),
            TestClock {},
        );
        assert_eq!(peers.valid_snapshots().count(), 0);

        peers
            .update(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    prev_epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
            )
            .await;
        assert_eq!(peers.valid_snapshots().count(), 0);

        peers
            .update(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(1.0),
                        NtpDuration::from_seconds(2.0),
                    ),
                ),
                epoch,
            )
            .await;
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers
            .update(
                MsgForSystem::NewMeasurement(
                    PeerIndex { index: 0 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
            )
            .await;
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers
            .update(
                MsgForSystem::UpdatedSnapshot(
                    PeerIndex { index: 1 },
                    epoch,
                    peer_snapshot(
                        PeerStatistics {
                            delay: NtpDuration::from_seconds(0.1),
                            offset: NtpDuration::from_seconds(0.),
                            dispersion: NtpDuration::from_seconds(0.05),
                            jitter: 0.05,
                        },
                        base,
                        NtpDuration::from_seconds(0.1),
                        NtpDuration::from_seconds(0.05),
                    ),
                ),
                epoch,
            )
            .await;
        assert_eq!(peers.valid_snapshots().count(), 2);

        peers
            .update(MsgForSystem::MustDemobilize(PeerIndex { index: 1 }), epoch)
            .await;
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers.reset_all();
        assert_eq!(peers.valid_snapshots().count(), 0);
    }

    #[tokio::test]
    async fn single_peer_pool() {
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();
        let peer_configs = vec![
            PeerConfig::Standard(StandardPeerConfig {
                addr: "127.0.0.0:123".to_string(),
            }),
            PeerConfig::Pool(PoolPeerConfig {
                addr: "127.0.0.1:123".to_string(),
                max_peers: 1,
            }),
        ];
        let mut peers =
            Peers::from_statuslist(&[PeerStatus::NoMeasurement; 2], &peer_configs, TestClock {});

        // we have 2 peers
        assert_eq!(peers.peers.len(), 2);

        // our pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }), epoch)
            .await;

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 2);
    }

    #[tokio::test]
    async fn max_peers_bigger_than_pool_size() {
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();
        let peer_configs = vec![
            PeerConfig::Standard(StandardPeerConfig {
                addr: "127.0.0.0:123".to_string(),
            }),
            PeerConfig::Pool(PoolPeerConfig {
                addr: "127.0.0.1:123".to_string(),
                max_peers: 2,
            }),
        ];
        let mut peers =
            Peers::from_statuslist(&[PeerStatus::NoMeasurement; 2], &peer_configs, TestClock {});

        // we have only 2 peers, because the pool has size 1
        assert_eq!(peers.peers.len(), 2);

        // our pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }), epoch)
            .await;

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 2);
    }
}
