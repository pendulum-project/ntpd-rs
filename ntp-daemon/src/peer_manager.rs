use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::{
    config::{NormalizedAddress, PeerConfig, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    observer::ObservablePeerState,
    peer::{MsgForSystem, PeerChannels, PeerTask, ResetEpoch},
    server::ServerTask,
};
use ntp_proto::{NtpClock, PeerSnapshot};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
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
pub(crate) enum PeerAddress {
    Peer {
        address: NormalizedAddress,
    },
    Pool {
        index: PoolIndex,
        address: NormalizedAddress,
        socket_address: std::net::SocketAddr,
        max_peers: usize,
    },
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

    pub(crate) fn spawn_task(
        &mut self,
        peer_address: PeerAddress,
        addr: SocketAddr,
    ) -> JoinHandle<()> {
        let index = self.peer_indexer.get();

        self.peers.insert(
            index,
            PeerState {
                status: PeerStatus::NoMeasurement,
                peer_address,
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

    /// Add a single standard peer
    async fn add_peer_internal(&mut self, address: NormalizedAddress) {
        let config = SpawnConfig::Standard {
            config: StandardPeerConfig { addr: address },
        };

        if let Err(e) = self.channels.spawn_config.send(config).await {
            warn!(?e, "spawn_config channel failed to add peer");
        }
    }

    /// Adds up to `max_peers` peers from a pool.
    pub async fn add_new_pool(&mut self, address: NormalizedAddress, max_peers: usize) {
        // Each pool gets a unique index, because the `NormalizedAddress` may not be unique
        // Having two pools use the same address does not really do anything good, but we
        // want to make sure it does technically work.
        let index = self.pool_indexer.get();

        self.add_to_pool(index, address, max_peers).await
    }

    pub async fn add_to_pool(
        &mut self,
        index: PoolIndex,
        address: NormalizedAddress,
        max_peers: usize,
    ) {
        println!("add to pool");

        let in_use: Vec<_> = self
            .peers
            .values()
            .filter_map(|v| match &v.peer_address {
                PeerAddress::Peer { .. } => None,
                PeerAddress::Pool {
                    index: pool_index,
                    socket_address,
                    ..
                } => (index == *pool_index).then_some(*socket_address),
            })
            .collect();

        let config = SpawnConfig::Pool {
            index,
            config: PoolPeerConfig {
                addr: address,
                max_peers,
            },
            in_use,
        };

        if let Err(e) = self.channels.spawn_config.send(config).await {
            warn!(?e, "spawn_config channel failed to add pool");
            println!("fail");
        }
        println!("sent");
    }

    /// Adds a single peer (that is not part of a pool!)
    pub async fn add_peer(&mut self, address: NormalizedAddress) {
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
                        max_peers,
                        ..
                    } => {
                        self.add_to_pool(index, address, max_peers).await;
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

#[derive(Debug, Default)]
pub struct Spawner {
    pools: HashMap<PoolIndex, Arc<tokio::sync::Mutex<PoolAddresses>>>,
}

#[derive(Debug, Default)]
struct PoolAddresses {
    backups: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum SpawnConfig {
    Standard {
        config: StandardPeerConfig,
    },
    Pool {
        index: PoolIndex,
        config: PoolPeerConfig,
        in_use: Vec<SocketAddr>,
    },
}

#[derive(Debug)]
pub struct SpawnTask {
    pub(crate) peer_address: PeerAddress,
    pub(crate) address: SocketAddr,
}

impl Spawner {
    pub(crate) async fn spawn(
        &mut self,
        mut input_channel: Receiver<SpawnConfig>,
        output_channel: Sender<SpawnTask>,
    ) {
        while let Some(config) = input_channel.recv().await {
            let sender = output_channel.clone();

            match dbg!(config) {
                SpawnConfig::Standard { config } => self.spawn_standard(config, sender).await,
                SpawnConfig::Pool {
                    config,
                    index,
                    in_use,
                } => self.spawn_pool(index, config, &in_use, sender).await,
            }
        }

        println!("receive failed");
    }

    async fn spawn_standard(&mut self, config: StandardPeerConfig, sender: Sender<SpawnTask>) {
        let addr = loop {
            match config.addr.lookup_host().await {
                Ok(mut addresses) => match addresses.next() {
                    None => {
                        warn!("Could not resolve peer address, retrying");
                        tokio::time::sleep(NETWORK_WAIT_PERIOD).await
                    }
                    Some(first) => {
                        break first;
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "error while resolving peer address, retrying");
                    tokio::time::sleep(NETWORK_WAIT_PERIOD).await
                }
            }
        };

        let spawn_task = SpawnTask {
            peer_address: PeerAddress::Peer {
                address: config.addr,
            },
            address: addr,
        };

        if let Err(send_error) = sender.send(spawn_task).await {
            tracing::error!(?send_error, "Receive half got disconnected");
        }
    }

    async fn spawn_pool(
        &mut self,
        pool_index: PoolIndex,
        config: PoolPeerConfig,
        in_use: &[SocketAddr],
        sender: Sender<SpawnTask>,
    ) {
        let mut wait_period = NETWORK_WAIT_PERIOD;
        let mut remaining;

        loop {
            let pool = self.pools.entry(pool_index).or_default();
            let mut pool = pool.lock().await;

            remaining = config.max_peers - in_use.len();

            tracing::trace!(?config.addr);

            if pool.backups.len() < config.max_peers - in_use.len() {
                tracing::trace!("we don't have enough backups; try to get more");
                match config.addr.lookup_host().await {
                    Ok(addresses) => {
                        pool.backups = addresses.collect();
                    }
                    Err(e) => {
                        warn!(error = ?e, "error while resolving peer address, retrying");
                        tokio::time::sleep(wait_period).await;
                        continue;
                    }
                }
            }

            tracing::trace!(?in_use, ?pool.backups);

            // then, empty out our backups
            while let Some(addr) = pool.backups.pop() {
                if remaining == 0 {
                    return;
                }

                debug_assert!(!in_use.contains(&addr));

                let spawn_task = SpawnTask {
                    peer_address: PeerAddress::Pool {
                        index: pool_index,
                        address: config.addr.clone(),
                        socket_address: addr,
                        max_peers: config.max_peers,
                    },
                    address: addr,
                };

                if let Err(send_error) = sender.send(spawn_task).await {
                    tracing::error!(?send_error, "Receive half got disconnected");
                }

                remaining -= 1;
            }

            if remaining == 0 {
                return;
            }

            wait_period = Ord::max(2 * wait_period, std::time::Duration::from_secs(60));

            warn!(?pool_index, remaining, "could not fully fill pool");
            tokio::time::sleep(wait_period).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntp_proto::{
        peer_snapshot, NtpDuration, NtpInstant, NtpLeapIndicator, NtpTimestamp, PeerStatistics,
        PollInterval, SystemConfig, SystemSnapshot,
    };

    use crate::config::{NormalizedAddress, StandardPeerConfig};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            // Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
            Ok(NtpTimestamp::default())
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

    #[tokio::test]
    async fn single_peer_pool() {
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();

        let mut peers = Peers::new(PeerChannels::test(), TestClock {});

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.0:123");
        peers.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::new_unchecked("127.0.0.1:123");
        let max_peers = 1;
        peers.add_new_pool(pool_address.clone(), max_peers).await;

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

        let mut peers = Peers::new(PeerChannels::test(), TestClock {});

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.0:123");
        peers.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::new_unchecked("127.0.0.1:123");
        let max_peers = 2;
        peers.add_new_pool(pool_address.clone(), max_peers).await;

        // we have only 2 peers, because the pool has size 1
        assert_eq!(peers.peers.len(), 2);

        // our pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }), epoch)
            .await;

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 2);
    }

    #[tokio::test]
    async fn simulate_pool() {
        tracing_subscriber::fmt::init();

        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();

        let (msg_for_system_sender, _) = tokio::sync::mpsc::channel(2);
        let (spawn_config, spawn_config_rx) = tokio::sync::mpsc::channel(32);
        let (_, reset) = tokio::sync::watch::channel(ResetEpoch::default());
        let peer_channels = PeerChannels {
            msg_for_system_sender,
            system_snapshots: Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default())),
            system_config: Arc::new(tokio::sync::RwLock::new(SystemConfig::default())),
            reset,
            spawn_config,
        };
        let mut peers = Peers::new(peer_channels, TestClock {});

        let (spawn_task_tx, mut spawn_task_rx) = tokio::sync::mpsc::channel(32);
        let _handle = tokio::spawn(async move {
            Spawner::default()
                .spawn(spawn_config_rx, spawn_task_tx)
                .await;
        });

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5:123");
        peers.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::with_hardcoded_dns(
            "tweedegolf.nl:123",
            vec![
                "127.0.0.1:123".parse().unwrap(),
                "127.0.0.2:123".parse().unwrap(),
                "127.0.0.3:123".parse().unwrap(),
                "127.0.0.4:123".parse().unwrap(),
            ],
        );
        let max_peers = 3;
        peers.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..4 {
            let task = spawn_task_rx.recv().await.unwrap();
            peers.spawn_task(task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(peers.peers.len(), 4);

        println!("----------------------");

        // simulate that a pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }), epoch)
            .await;

        let task = spawn_task_rx.recv().await.unwrap();
        peers.spawn_task(task.peer_address, task.address);

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 4);
    }
}
