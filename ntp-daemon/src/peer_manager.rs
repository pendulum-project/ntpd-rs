use std::{collections::HashMap, sync::Arc};

use crate::{
    config::{NormalizedAddress, ServerConfig},
    observer::ObservablePeerState,
    peer::{MsgForSystem, PeerChannels, PeerTask, ResetEpoch},
    server::ServerTask,
};
use ntp_proto::{NtpClock, PeerSnapshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

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
        Self { index }
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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PoolIndex {
    index: usize,
}

#[derive(Debug, Default)]
struct PoolIndexIssuer {
    next: usize,
}

impl PoolIndexIssuer {
    fn get(&mut self) -> PoolIndex {
        let index = self.next;
        self.next += 1;
        PoolIndex { index }
    }
}

#[derive(Debug)]
enum PeerAddress {
    Peer {
        address: NormalizedAddress,
    },
    Pool {
        index: PoolIndex,
        address: NormalizedAddress,
        socket_address: std::net::SocketAddr,
        /// socket addresses that we have resolved but not yet used
        cached: CachedPoolAddresses,
    },
}

#[derive(Debug, Clone, Default)]
struct CachedPoolAddresses {
    cached: Arc<tokio::sync::Mutex<Vec<std::net::SocketAddr>>>,
}

impl CachedPoolAddresses {
    /// Find additional peers from the pool
    ///
    /// - will do a DNS resolve if there are insufficient `backups`
    /// - will never add more than `max_peers` active peers from the pool
    async fn find_additional<I>(
        &mut self,
        address: &NormalizedAddress,
        active_pool_peers: I,
    ) -> Option<std::net::SocketAddr>
    where
        I: IntoIterator<Item = std::net::SocketAddr>,
    {
        let mut cached = self.cached.lock().await;

        match cached.pop() {
            Some(addr) => Some(addr),
            None => {
                // there are not enough cached peers; try and get more with DNS resolve
                let (first, mut new) = socket_addresses(address).await;
                new.push(first);

                for peer in active_pool_peers {
                    new.retain(|socket_addr| *socket_addr != peer);
                }

                *cached = new;

                cached.pop()
            }
        }
    }
}

/// Get available socket addresses for a host
async fn socket_addresses(
    address: &NormalizedAddress,
) -> (std::net::SocketAddr, Vec<std::net::SocketAddr>) {
    loop {
        match address.lookup_host().await {
            Ok(mut addresses) => match addresses.next() {
                None => {
                    warn!("Could not resolve peer address, retrying");
                    tokio::time::sleep(NETWORK_WAIT_PERIOD).await
                }
                Some(first) => {
                    return (first, addresses.collect());
                }
            },
            Err(e) => {
                warn!(error = ?e, "error while resolving peer address, retrying");
                tokio::time::sleep(NETWORK_WAIT_PERIOD).await
            }
        }
    }
}

#[derive(Debug)]
struct PeerState {
    status: PeerStatus,
    peer_address: PeerAddress,
}

#[derive(Debug)]
pub struct Peers<C: NtpClock> {
    peers: HashMap<PeerIndex, PeerState>,
    servers: Vec<Arc<ServerConfig>>,
    peer_indexer: PeerIndexIssuer,
    pool_indexer: PoolIndexIssuer,

    channels: PeerChannels,
    clock: C,
}

impl<C: NtpClock> Peers<C> {
    pub fn new(channels: PeerChannels, clock: C) -> Self {
        Peers {
            peers: Default::default(),
            servers: Default::default(),
            peer_indexer: Default::default(),
            pool_indexer: Default::default(),
            channels,
            clock,
        }
    }

    /// Add a single peer to an existing pool
    async fn add_pool_peer_internal(
        &mut self,
        address: NormalizedAddress,
        mut cached: CachedPoolAddresses,
        pool_index: PoolIndex,
    ) -> Option<JoinHandle<()>> {
        let index = self.peer_indexer.get();

        // socket addresses of the peers of this pool that are currently active
        let active_pool_peers = self.peers.values().filter_map(|p| match &p.peer_address {
            PeerAddress::Peer { .. } => None,
            PeerAddress::Pool {
                index: peer_pool_index,
                socket_address,
                ..
            } => {
                if pool_index == *peer_pool_index {
                    Some(*socket_address)
                } else {
                    None
                }
            }
        });

        // if no socket addresses are cached, do a new DNS resolve
        let addr = match cached.find_additional(&address, active_pool_peers).await {
            Some(addr) => addr,
            None => {
                warn!(?address, "all socket addresses from this pool are currently in use; is the pool configured correctly?");
                return None;
            }
        };

        self.peers.insert(
            index,
            PeerState {
                status: PeerStatus::NoMeasurement,
                peer_address: PeerAddress::Pool {
                    index: pool_index,
                    address,
                    socket_address: addr,
                    cached,
                },
            },
        );

        Some(PeerTask::spawn(
            index,
            addr,
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
            self.channels.clone(),
        ))
    }

    /// Add a single standard peer
    async fn add_peer_internal(&mut self, address: NormalizedAddress) -> JoinHandle<()> {
        let index = self.peer_indexer.get();

        // socket_addresses guarantees there is at least one element in the iterator
        let (addr, _rest) = socket_addresses(&address).await;
        debug!(resolved=?addr, "resolved peer");

        self.peers.insert(
            index,
            PeerState {
                status: PeerStatus::NoMeasurement,
                peer_address: PeerAddress::Peer { address },
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

    /// Adds up to `max_peers` peers from a pool.
    pub async fn add_pool(
        &mut self,
        address: NormalizedAddress,
        max_peers: usize,
    ) -> Vec<JoinHandle<()>> {
        // Each pool gets a unique index, because the `NormalizedAddress` may not be unique
        // Having two pools use the same address does not really do anything good, but we
        // want to make sure it does technically work.
        let index = self.pool_indexer.get();

        let mut handles = Vec::with_capacity(max_peers);
        let cached = CachedPoolAddresses::default();

        for _ in 0..max_peers {
            handles.extend(
                self.add_pool_peer_internal(address.clone(), cached.clone(), index)
                    .await,
            );
        }

        handles
    }

    /// Adds a single peer (that is not part of a pool!)
    pub async fn add_peer(&mut self, address: NormalizedAddress) -> JoinHandle<()> {
        self.add_peer_internal(address).await
    }

    fn add_server_internal(&mut self, config: Arc<ServerConfig>) -> JoinHandle<()> {
        self.servers.push(config.clone());
        ServerTask::spawn(
            config,
            self.channels.system_snapshots.clone(),
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
        )
    }

    pub async fn add_server(&mut self, config: ServerConfig) -> JoinHandle<()> {
        self.add_server_internal(Arc::new(config))
    }

    #[cfg(test)]
    pub fn from_statuslist(
        data: &[PeerStatus],
        raw_configs: &[crate::config::PeerConfig],
        clock: C,
    ) -> Self {
        use crate::config::{PeerConfig, PoolPeerConfig, StandardPeerConfig};

        assert_eq!(data.len(), raw_configs.len());

        let mut peers = HashMap::new();
        let mut peer_indexer = PeerIndexIssuer::default();

        for (i, status) in data.iter().enumerate() {
            let index = peer_indexer.get();

            match &raw_configs[i] {
                PeerConfig::Standard(StandardPeerConfig { addr }) => {
                    peers.insert(
                        index,
                        PeerState {
                            status: status.to_owned(),
                            peer_address: PeerAddress::Peer {
                                address: addr.clone(),
                            },
                        },
                    );
                }
                PeerConfig::Pool(PoolPeerConfig { .. }) => {
                    unimplemented!()
                }
            };
        }

        Self {
            peers,
            servers: vec![],
            peer_indexer,
            pool_indexer: Default::default(),
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
                address: match &data.peer_address {
                    PeerAddress::Peer { address } => address.as_str().to_string(),
                    PeerAddress::Pool { address, .. } => address.as_str().to_string(),
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
                let config = self.peers.remove(&index).unwrap().peer_address;

                match config {
                    PeerAddress::Peer { address } => {
                        self.add_peer_internal(address).await;
                    }
                    PeerAddress::Pool {
                        index,
                        address,
                        cached,
                        ..
                    } => {
                        self.add_pool_peer_internal(address, cached, index).await;
                    }
                }
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

    use crate::config::{NormalizedAddress, StandardPeerConfig};

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
        use crate::config::PeerConfig;

        let base = NtpInstant::now();
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();
        let mut peers = Peers::from_statuslist(
            &[PeerStatus::NoMeasurement; 4],
            &(0..4)
                .map(|i| {
                    PeerConfig::Standard(StandardPeerConfig {
                        addr: NormalizedAddress::new_unchecked(&format!("127.0.0.{i}:123")),
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
}
