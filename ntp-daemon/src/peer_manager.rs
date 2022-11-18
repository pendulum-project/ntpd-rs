use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::{
    config::{NormalizedAddress, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    observer::ObservablePeerState,
    peer::{MsgForSystem, PeerChannels, PeerTask},
    server::{ServerStats, ServerTask},
};
use ntp_proto::{
    DefaultTimeSyncController, NtpClock, PeerSnapshot, SystemConfig, TimeSnapshot,
    TimeSyncController,
};
use tokio::{sync::mpsc::Sender, task::JoinHandle};
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

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}

#[derive(Debug)]
pub struct Peers<C: NtpClock> {
    peers: HashMap<PeerIndex, PeerState>,
    servers: Vec<ServerData>,
    spawner: Spawner,
    peer_indexer: PeerIndexIssuer,
    pool_indexer: PoolIndexIssuer,

    channels: PeerChannels,
    clock: C,

    controller: DefaultTimeSyncController<C, PeerIndex>,
    config: SystemConfig,
}

impl<C: NtpClock> Peers<C> {
    pub fn new(
        channels: PeerChannels,
        clock: C,
        spawn_task: Sender<SpawnTask>,
        config: SystemConfig,
    ) -> Self {
        Peers {
            peers: Default::default(),
            servers: Default::default(),
            spawner: Spawner {
                pools: Default::default(),
                sender: spawn_task,
            },
            peer_indexer: Default::default(),
            pool_indexer: Default::default(),
            channels,
            clock: clock.clone(),
            controller: DefaultTimeSyncController::new(clock, config),
            config,
        }
    }

    pub(crate) fn spawn_task(&mut self, peer_address: PeerAddress, addr: SocketAddr) {
        let index = self.peer_indexer.get();

        self.peers.insert(
            index,
            PeerState {
                status: PeerStatus::NoMeasurement,
                peer_address,
            },
        );
        self.controller.peer_add(index);
        PeerTask::spawn(
            index,
            addr,
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
            self.channels.clone(),
        );
    }

    /// Add a single standard peer
    async fn add_peer_internal(&mut self, address: NormalizedAddress) {
        let config = SpawnConfig::Standard {
            config: StandardPeerConfig { addr: address },
        };

        self.spawner.spawn(config).await;
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
        let in_use: Vec<_> = self
            .peers
            .values()
            .filter_map(|v| match &v.peer_address {
                PeerAddress::Peer { .. } => None,
                PeerAddress::Pool {
                    index: pool_index,
                    address: peer_address,
                    socket_address,
                    ..
                } => {
                    let in_this_pool = index == *pool_index;
                    let not_removed_peer = peer_address != &address;
                    (in_this_pool && not_removed_peer).then_some(*socket_address)
                }
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

        self.spawner.spawn(config).await;
    }

    /// Adds a single peer (that is not part of a pool!)
    pub async fn add_peer(&mut self, address: NormalizedAddress) {
        self.add_peer_internal(address).await
    }

    pub async fn add_server(&mut self, config: ServerConfig) -> JoinHandle<()> {
        let stats = ServerStats::default();
        self.servers.push(ServerData {
            stats: stats.clone(),
            config: config.clone(),
        });
        ServerTask::spawn(
            config,
            stats,
            self.channels.system_snapshots.clone(),
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
        )
    }

    #[cfg(test)]
    pub fn from_statuslist(
        data: &[PeerStatus],
        raw_configs: &[crate::config::PeerConfig],
        clock: C,
    ) -> Self {
        use crate::config::PeerConfig;

        assert_eq!(data.len(), raw_configs.len());

        let mut peers = HashMap::new();
        let mut peer_indexer = PeerIndexIssuer::default();
        let mut controller = DefaultTimeSyncController::new(clock.clone(), SystemConfig::default());

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
                    unimplemented!("this testing function does not support pool configs")
                }
            };
            controller.peer_add(index);
        }

        let (spawn_task_tx, _spawn_task_rx) = tokio::sync::mpsc::channel(32);

        Self {
            peers,
            servers: vec![],
            spawner: Spawner {
                pools: Default::default(),
                sender: spawn_task_tx,
            },
            peer_indexer,
            pool_indexer: Default::default(),
            channels: PeerChannels::test(),
            clock,
            controller,
            config: SystemConfig::default(),
        }
    }

    pub fn size(&self) -> usize {
        self.peers.len()
    }

    pub fn observe_peers(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(index, data)| match data.status {
            PeerStatus::NoMeasurement => ObservablePeerState::Nothing,
            PeerStatus::Measurement(snapshot) => {
                if let Some(timedata) = self.controller.peer_snapshot(*index) {
                    ObservablePeerState::Observable {
                        statistics: timedata.statistics,
                        reachability: snapshot.reach,
                        uptime: timedata.time.elapsed(),
                        poll_interval: snapshot.poll_interval,
                        peer_id: snapshot.peer_id,
                        address: match &data.peer_address {
                            PeerAddress::Peer { address } => address.as_str().to_string(),
                            PeerAddress::Pool { address, .. } => address.as_str().to_string(),
                        },
                    }
                } else {
                    ObservablePeerState::Nothing
                }
            }
        })
    }

    pub fn peer_snapshot(&self, index: PeerIndex) -> Option<PeerSnapshot> {
        self.peers.get(&index).and_then(|data| match data.status {
            PeerStatus::NoMeasurement => None,
            PeerStatus::Measurement(snapshot) => Some(snapshot),
        })
    }

    pub fn servers(&self) -> impl Iterator<Item = ServerData> + '_ {
        self.servers.iter().cloned()
    }

    pub fn update_config(&mut self, config: SystemConfig) {
        self.controller.update_config(config);
        self.config = config;
    }

    pub async fn update(&mut self, msg: MsgForSystem) -> Option<(Vec<PeerIndex>, TimeSnapshot)> {
        tracing::debug!(?msg, "updating peer");

        match msg {
            MsgForSystem::MustDemobilize(index) => {
                self.controller.peer_remove(index);
                self.peers.remove(&index);
                None
            }
            MsgForSystem::NewMeasurement(index, snapshot, measurement, packet) => {
                self.controller.peer_update(
                    index,
                    snapshot
                        .accept_synchronization(self.config.local_stratum)
                        .is_ok(),
                );
                self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                self.controller.peer_measurement(index, measurement, packet)
            }
            MsgForSystem::UpdatedSnapshot(index, snapshot) => {
                self.controller.peer_update(
                    index,
                    snapshot
                        .accept_synchronization(self.config.local_stratum)
                        .is_ok(),
                );
                self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                None
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

                None
            }
        }
    }
}

#[derive(Debug)]
pub struct Spawner {
    pools: HashMap<PoolIndex, Arc<tokio::sync::Mutex<PoolAddresses>>>,
    sender: Sender<SpawnTask>,
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
    pub(crate) async fn spawn(&mut self, config: SpawnConfig) -> tokio::task::JoinHandle<()> {
        let sender = self.sender.clone();

        match config {
            SpawnConfig::Standard { config } => tokio::spawn(Self::spawn_standard(config, sender)),

            SpawnConfig::Pool {
                config,
                index,
                in_use,
            } => {
                let pool = self.pools.entry(index).or_default().clone();
                tokio::spawn(Self::spawn_pool(index, pool, config, in_use, sender))
            }
        }
    }

    async fn spawn_standard(config: StandardPeerConfig, sender: Sender<SpawnTask>) {
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
        pool_index: PoolIndex,
        pool: Arc<tokio::sync::Mutex<PoolAddresses>>,
        config: PoolPeerConfig,
        in_use: Vec<SocketAddr>,
        sender: Sender<SpawnTask>,
    ) {
        let mut wait_period = NETWORK_WAIT_PERIOD;
        let mut remaining;

        loop {
            let mut pool = pool.lock().await;

            remaining = config.max_peers - in_use.len();

            if pool.backups.len() < config.max_peers - in_use.len() {
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

                tracing::debug!(?spawn_task, "intending to spawn new pool peer at");

                if let Err(send_error) = sender.send(spawn_task).await {
                    tracing::error!(?send_error, "Receive half got disconnected");
                }

                remaining -= 1;
            }

            if remaining == 0 {
                return;
            }

            let wait_period_max = if cfg!(test) {
                std::time::Duration::default()
            } else {
                std::time::Duration::from_secs(60)
            };

            wait_period = Ord::min(2 * wait_period, wait_period_max);

            warn!(?pool_index, remaining, "could not fully fill pool");
            tokio::time::sleep(wait_period).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::{
        peer_snapshot, Measurement, NtpDuration, NtpInstant, NtpLeapIndicator, NtpPacket,
        NtpTimestamp, PollInterval, SystemConfig, SystemSnapshot,
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
        let base = NtpInstant::now();
        assert_eq!(
            peers
                .peers
                .values()
                .map(|v| match v.status {
                    PeerStatus::Measurement(_) => 1,
                    PeerStatus::NoMeasurement => 0,
                })
                .sum::<i32>(),
            0
        );

        peers
            .update(MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                peer_snapshot(),
                Measurement {
                    delay: NtpDuration::from_seconds(0.1),
                    offset: NtpDuration::from_seconds(0.),
                    localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                    monotime: base,
                },
                NtpPacket::test(),
            ))
            .await;
        assert_eq!(
            peers
                .peers
                .values()
                .map(|v| match v.status {
                    PeerStatus::Measurement(_) => 1,
                    PeerStatus::NoMeasurement => 0,
                })
                .sum::<i32>(),
            1
        );

        peers
            .update(MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                peer_snapshot(),
                Measurement {
                    delay: NtpDuration::from_seconds(0.1),
                    offset: NtpDuration::from_seconds(0.),
                    localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                    monotime: base,
                },
                NtpPacket::test(),
            ))
            .await;
        assert_eq!(
            peers
                .peers
                .values()
                .map(|v| match v.status {
                    PeerStatus::Measurement(_) => 1,
                    PeerStatus::NoMeasurement => 0,
                })
                .sum::<i32>(),
            1
        );

        peers
            .update(MsgForSystem::UpdatedSnapshot(
                PeerIndex { index: 1 },
                peer_snapshot(),
            ))
            .await;
        assert_eq!(
            peers
                .peers
                .values()
                .map(|v| match v.status {
                    PeerStatus::Measurement(_) => 1,
                    PeerStatus::NoMeasurement => 0,
                })
                .sum::<i32>(),
            2
        );

        peers
            .update(MsgForSystem::MustDemobilize(PeerIndex { index: 1 }))
            .await;
        assert_eq!(
            peers
                .peers
                .values()
                .map(|v| match v.status {
                    PeerStatus::Measurement(_) => 1,
                    PeerStatus::NoMeasurement => 0,
                })
                .sum::<i32>(),
            1
        );
    }

    #[tokio::test]
    async fn single_peer_pool() {
        let (spawn_task_tx, mut spawn_task_rx) = tokio::sync::mpsc::channel(32);
        let mut peers = Peers::new(
            PeerChannels::test(),
            TestClock {},
            spawn_task_tx,
            SystemConfig::default(),
        );

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.2:123");
        peers.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::new_unchecked("127.0.0.1:123");
        let max_peers = 1;
        peers.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = spawn_task_rx.recv().await.unwrap();
            peers.spawn_task(task.peer_address, task.address);
        }

        // we have 2 peers
        assert_eq!(peers.peers.len(), 2);

        // our pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        for _ in 0..1 {
            let task = spawn_task_rx.recv().await.unwrap();
            peers.spawn_task(task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 2);
    }

    #[tokio::test]
    async fn max_peers_bigger_than_pool_size() {
        let (msg_for_system_sender, _) = tokio::sync::mpsc::channel(2);
        let (_, system_config_receiver) = tokio::sync::watch::channel(SystemConfig::default());
        let peer_channels = PeerChannels {
            msg_for_system_sender,
            system_snapshots: Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default())),
            system_config_receiver,
        };

        let (spawn_task_tx, mut spawn_task_rx) = tokio::sync::mpsc::channel(32);
        let mut peers = Peers::new(
            peer_channels,
            TestClock {},
            spawn_task_tx,
            SystemConfig::default(),
        );

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5:123");
        peers.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::with_hardcoded_dns(
            "tweedegolf.nl:123",
            vec!["127.0.0.1:123".parse().unwrap()],
        );
        let max_peers = 2;
        peers.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = spawn_task_rx.recv().await.unwrap();
            peers.spawn_task(task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(peers.peers.len(), 2);

        dbg!("initial spawns completed");

        // our pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        for _ in 0..1 {
            dbg!("waiting");
            let task = spawn_task_rx.recv().await.unwrap();
            dbg!(&task);
            peers.spawn_task(task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 2);
    }

    #[tokio::test]
    async fn simulate_pool() {
        let (msg_for_system_sender, _) = tokio::sync::mpsc::channel(2);
        let (_, system_config_receiver) = tokio::sync::watch::channel(SystemConfig::default());
        let peer_channels = PeerChannels {
            msg_for_system_sender,
            system_snapshots: Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default())),
            system_config_receiver,
        };

        let (spawn_task_tx, mut spawn_task_rx) = tokio::sync::mpsc::channel(32);
        let mut peers = Peers::new(
            peer_channels,
            TestClock {},
            spawn_task_tx,
            SystemConfig::default(),
        );

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

        // simulate that a pool peer has a network issue
        peers
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        let task = spawn_task_rx.recv().await.unwrap();
        peers.spawn_task(task.peer_address, task.address);

        // automatically selects another peer from the pool
        assert_eq!(peers.peers.len(), 4);
    }
}
