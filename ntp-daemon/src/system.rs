use crate::{
    config::NormalizedAddress,
    config::{PeerConfig, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    peer::PeerTask,
    peer::{MsgForSystem, PeerChannels},
    server::{ServerStats, ServerTask},
    ObservablePeerState,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    DefaultTimeSyncController, NtpClock, PeerSnapshot, SystemConfig, SystemSnapshot, TimeSnapshot,
    TimeSyncController,
};
use tokio::{
    sync::mpsc::{self, Sender},
    task::JoinHandle,
};
use tracing::warn;

const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

pub struct DaemonChannels {
    pub config_receiver: tokio::sync::watch::Receiver<SystemConfig>,
    pub config_sender: tokio::sync::watch::Sender<SystemConfig>,
    pub peer_snapshots_receiver: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
}

/// Spawn the NTP daemon
pub async fn spawn(
    config: SystemConfig,
    peer_configs: &[PeerConfig],
    server_configs: &[ServerConfig],
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)> {
    let clock = UnixNtpClock::new();
    let (mut system, channels) = System::new(clock, config);

    for peer_config in peer_configs {
        match peer_config {
            PeerConfig::Standard(StandardPeerConfig { addr }) => {
                system.add_peer(addr.clone()).await;
            }
            PeerConfig::Pool(PoolPeerConfig {
                addr, max_peers, ..
            }) => {
                system.add_new_pool(addr.clone(), *max_peers).await;
            }
        }
    }

    for server_config in server_configs.iter() {
        system.add_server(server_config.to_owned()).await;
    }

    system.update_snapshots_post_spawn();

    let handle = tokio::spawn(async move { system.run().await });

    Ok((handle, channels))
}

struct System<C: NtpClock> {
    config: SystemConfig,
    system: SystemSnapshot,

    config_receiver: tokio::sync::watch::Receiver<SystemConfig>,
    system_snapshot_sender: tokio::sync::watch::Sender<SystemSnapshot>,
    peer_snapshots_sender: tokio::sync::watch::Sender<Vec<ObservablePeerState>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    spawn_task_rx: mpsc::Receiver<SpawnTask>,

    peers: HashMap<PeerIndex, PeerState>,
    servers: Vec<ServerData>,
    spawner: Spawner,
    peer_indexer: PeerIndexIssuer,
    pool_indexer: PoolIndexIssuer,

    peer_channels: PeerChannels,

    clock: C,
    controller: DefaultTimeSyncController<C, PeerIndex>,
}

impl<C: NtpClock> System<C> {
    const MESSAGE_BUFFER_SIZE: usize = 32;

    fn new(clock: C, config: SystemConfig) -> (Self, DaemonChannels) {
        // Setup system snapshot
        let system = SystemSnapshot {
            stratum: config.local_stratum,
            ..Default::default()
        };

        // Create communication channels
        let (config_sender, config_receiver) = tokio::sync::watch::channel(config);
        let (system_snapshot_sender, system_snapshot_receiver) =
            tokio::sync::watch::channel(system);
        let (peer_snapshots_sender, peer_snapshots_receiver) = tokio::sync::watch::channel(vec![]);
        let (server_data_sender, server_data_receiver) = tokio::sync::watch::channel(vec![]);
        let (spawn_task_sender, spawn_task_receiver) =
            tokio::sync::mpsc::channel(Self::MESSAGE_BUFFER_SIZE);
        let (msg_for_system_sender, msg_for_system_receiver) =
            tokio::sync::mpsc::channel(Self::MESSAGE_BUFFER_SIZE);

        // Build System and its channels
        (
            System {
                config,
                system,

                config_receiver: config_receiver.clone(),
                system_snapshot_sender,
                peer_snapshots_sender,
                server_data_sender,

                msg_for_system_rx: msg_for_system_receiver,
                spawn_task_rx: spawn_task_receiver,

                peers: Default::default(),
                servers: Default::default(),
                spawner: Spawner {
                    pools: Default::default(),
                    sender: spawn_task_sender,
                },
                peer_indexer: Default::default(),
                pool_indexer: Default::default(),
                peer_channels: PeerChannels {
                    msg_for_system_sender,
                    system_snapshot_receiver: system_snapshot_receiver.clone(),
                    system_config_receiver: config_receiver.clone(),
                },
                clock: clock.clone(),
                controller: DefaultTimeSyncController::new(clock, config),
            },
            DaemonChannels {
                config_receiver,
                config_sender,
                peer_snapshots_receiver,
                server_data_receiver,
                system_snapshot_receiver,
            },
        )
    }

    async fn run(&mut self) -> std::io::Result<()> {
        //let mut snapshots = Vec::with_capacity(self.peers_rwlock.read().await.size());

        loop {
            tokio::select! {
                opt_msg_for_system = self.msg_for_system_rx.recv() => {
                    match opt_msg_for_system {
                        None => {
                            // the channel closed and has no more messages in it
                            break
                        }
                        Some(msg_for_system) => {
                            let result = self
                                .update(msg_for_system)
                                .await;

                            if let Some((used_peers, timedata)) = result {
                                let system_peer_snapshot = self
                                    .peer_snapshot(used_peers[0])
                                    .unwrap();
                                self.system.time_snapshot = timedata;
                                self.system.stratum = system_peer_snapshot
                                    .stratum
                                    .saturating_add(1);
                                self.system.reference_id = system_peer_snapshot.reference_id;
                                self.system.accumulated_steps_threshold = self.config.accumulated_threshold;
                                // Don't care if there is no receiver.
                                let _ = self.system_snapshot_sender.send(self.system);
                            }

                            // Don't care if there is no receiver for peer snapshots (which might happen if
                            // we don't enable observing in the configuration)
                            let _ = self.peer_snapshots_sender.send(self.observe_peers().collect());
                        }
                    }
                }
                opt_spawn_task = self.spawn_task_rx.recv() => {
                    match opt_spawn_task {
                        None => {
                            // the channel closed and has no more messages in it
                            tracing::warn!("the spawn channel closed unexpectedly");
                        }
                        Some(spawn_task) => {
                            self
                                .spawn_task(spawn_task.peer_address, spawn_task.address);

                            self.update_snapshots_post_spawn();
                        }
                    }
                }
                _ = self.config_receiver.changed(), if self.config_receiver.has_changed().is_ok() => {
                    let config = *self.config_receiver.borrow_and_update();
                    self.update_config(config);
                    self.config = config;
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }

    fn update_snapshots_post_spawn(&self) {
        // Don't care if there is no receiver for peer snapshots (which might happen if
        // we don't enable observing in the configuration)
        let _ = self
            .peer_snapshots_sender
            .send(self.observe_peers().collect());
        let _ = self.server_data_sender.send(self.servers().collect());
    }

    #[cfg(test)]
    fn create_test_peer(&mut self, addr: NormalizedAddress) -> PeerIndex {
        let index = self.peer_indexer.get();

        self.peers.insert(
            index,
            PeerState {
                snapshot: None,
                peer_address: PeerAddress::Peer { address: addr },
            },
        );
        self.controller.peer_add(index);

        index
    }

    fn spawn_task(&mut self, peer_address: PeerAddress, addr: SocketAddr) {
        let index = self.peer_indexer.get();

        self.peers.insert(
            index,
            PeerState {
                snapshot: None,
                peer_address,
            },
        );
        self.controller.peer_add(index);
        PeerTask::spawn(
            index,
            addr,
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
            self.peer_channels.clone(),
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
    async fn add_new_pool(&mut self, address: NormalizedAddress, max_peers: usize) {
        // Each pool gets a unique index, because the `NormalizedAddress` may not be unique
        // Having two pools use the same address does not really do anything good, but we
        // want to make sure it does technically work.
        let index = self.pool_indexer.get();

        self.add_to_pool(index, address, max_peers).await
    }

    async fn add_to_pool(
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
    async fn add_peer(&mut self, address: NormalizedAddress) {
        self.add_peer_internal(address).await
    }

    async fn add_server(&mut self, config: ServerConfig) -> JoinHandle<()> {
        let stats = ServerStats::default();
        self.servers.push(ServerData {
            stats: stats.clone(),
            config: config.clone(),
        });
        ServerTask::spawn(
            config,
            stats,
            self.peer_channels.system_snapshot_receiver.clone(),
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
        )
    }

    pub fn observe_peers(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(index, data)| {
            data.snapshot
                .map(|snapshot| {
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
                })
                .unwrap_or(ObservablePeerState::Nothing)
        })
    }

    fn peer_snapshot(&self, index: PeerIndex) -> Option<PeerSnapshot> {
        self.peers.get(&index).and_then(|data| data.snapshot)
    }

    fn servers(&self) -> impl Iterator<Item = ServerData> + '_ {
        self.servers.iter().cloned()
    }

    fn update_config(&mut self, config: SystemConfig) {
        self.controller.update_config(config);
        self.config = config;
    }

    async fn update(&mut self, msg: MsgForSystem) -> Option<(Vec<PeerIndex>, TimeSnapshot)> {
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
                self.peers.get_mut(&index).unwrap().snapshot = Some(snapshot);
                self.controller.peer_measurement(index, measurement, packet)
            }
            MsgForSystem::UpdatedSnapshot(index, snapshot) => {
                self.controller.peer_update(
                    index,
                    snapshot
                        .accept_synchronization(self.config.local_stratum)
                        .is_ok(),
                );
                self.peers.get_mut(&index).unwrap().snapshot = Some(snapshot);
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
struct PoolIndex {
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
        max_peers: usize,
    },
}

#[derive(Debug)]
struct PeerState {
    snapshot: Option<PeerSnapshot>,
    peer_address: PeerAddress,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}

#[derive(Debug)]
struct Spawner {
    pools: HashMap<PoolIndex, Arc<tokio::sync::Mutex<PoolAddresses>>>,
    sender: Sender<SpawnTask>,
}

#[derive(Debug, Default)]
struct PoolAddresses {
    backups: Vec<SocketAddr>,
}

#[derive(Debug)]
enum SpawnConfig {
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
struct SpawnTask {
    peer_address: PeerAddress,
    address: SocketAddr,
}

impl Spawner {
    async fn spawn(&mut self, config: SpawnConfig) -> tokio::task::JoinHandle<()> {
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
        NtpTimestamp, PollInterval, SystemConfig,
    };

    use crate::config::NormalizedAddress;

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
        let (mut system, _) = System::new(TestClock {}, SystemConfig::default());

        let mut indices = [PeerIndex { index: 0 }; 4];

        for (i, item) in indices.iter_mut().enumerate() {
            *item = system.create_test_peer(NormalizedAddress::new_unchecked(&format!(
                "127.0.0.{i}:123"
            )));
        }

        let base = NtpInstant::now();
        assert_eq!(
            system
                .peers
                .values()
                .map(|v| match v.snapshot {
                    Some(_) => 1,
                    None => 0,
                })
                .sum::<i32>(),
            0
        );

        system
            .update(MsgForSystem::NewMeasurement(
                indices[0],
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
            system
                .peers
                .values()
                .map(|v| match v.snapshot {
                    Some(_) => 1,
                    None => 0,
                })
                .sum::<i32>(),
            1
        );

        system
            .update(MsgForSystem::NewMeasurement(
                indices[0],
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
            system
                .peers
                .values()
                .map(|v| match v.snapshot {
                    Some(_) => 1,
                    None => 0,
                })
                .sum::<i32>(),
            1
        );

        system
            .update(MsgForSystem::UpdatedSnapshot(indices[1], peer_snapshot()))
            .await;
        assert_eq!(
            system
                .peers
                .values()
                .map(|v| match v.snapshot {
                    Some(_) => 1,
                    None => 0,
                })
                .sum::<i32>(),
            2
        );

        system
            .update(MsgForSystem::MustDemobilize(indices[1]))
            .await;
        assert_eq!(
            system
                .peers
                .values()
                .map(|v| match v.snapshot {
                    Some(_) => 1,
                    None => 0,
                })
                .sum::<i32>(),
            1
        );
    }

    #[tokio::test]
    async fn single_peer_pool() {
        let (mut system, _) = System::new(TestClock {}, SystemConfig::default());

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.2:123");
        system.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::new_unchecked("127.0.0.1:123");
        let max_peers = 1;
        system.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            system.spawn_task(task.peer_address, task.address);
        }

        // we have 2 peers
        assert_eq!(system.peers.len(), 2);

        // our pool peer has a network issue
        system
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        for _ in 0..1 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            system.spawn_task(task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 2);
    }

    #[tokio::test]
    async fn max_peers_bigger_than_pool_size() {
        let (mut system, _) = System::new(TestClock {}, SystemConfig::default());

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5:123");
        system.add_peer(peer_address).await;

        let pool_address = NormalizedAddress::with_hardcoded_dns(
            "tweedegolf.nl:123",
            vec!["127.0.0.1:123".parse().unwrap()],
        );
        let max_peers = 2;
        system.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            system.spawn_task(task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(system.peers.len(), 2);

        dbg!("initial spawns completed");

        // our pool peer has a network issue
        system
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        for _ in 0..1 {
            dbg!("waiting");
            let task = system.spawn_task_rx.recv().await.unwrap();
            dbg!(&task);
            system.spawn_task(task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 2);
    }

    #[tokio::test]
    async fn simulate_pool() {
        let (mut system, _) = System::new(TestClock {}, SystemConfig::default());

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5:123");
        system.add_peer(peer_address).await;

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
        system.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..4 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            system.spawn_task(task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(system.peers.len(), 4);

        // simulate that a pool peer has a network issue
        system
            .update(MsgForSystem::NetworkIssue(PeerIndex { index: 1 }))
            .await;

        let task = system.spawn_task_rx.recv().await.unwrap();
        system.spawn_task(task.peer_address, task.address);

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 4);
    }
}
