use crate::{
    config::{CombinedSystemConfig, NormalizedAddress, PeerConfig, ServerConfig},
    peer::{MsgForSystem, PeerChannels},
    peer::{PeerTask, Wait},
    server::{ServerStats, ServerTask},
    spawn::{
        nts::NtsSpawner, pool::PoolSpawner, standard::StandardSpawner, PeerId, PeerRemovalReason,
        RemovedPeer, SpawnAction, SpawnEvent, Spawner, SpawnerId,
    },
    ObservablePeerState,
};

use std::{collections::HashMap, future::Future, marker::PhantomData, pin::Pin};

use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    DefaultTimeSyncController, NtpClock, NtpDuration, PeerSnapshot, SystemSnapshot,
    TimeSyncController,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::info;

pub const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

struct SingleshotSleep<T> {
    enabled: bool,
    sleep: Pin<Box<T>>,
}

impl<T: Wait> SingleshotSleep<T> {
    fn new_disabled(t: T) -> Self {
        SingleshotSleep {
            enabled: false,
            sleep: Box::pin(t),
        }
    }
}

impl<T: Wait> Future for SingleshotSleep<T> {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if !this.enabled {
            return std::task::Poll::Pending;
        }
        match this.sleep.as_mut().poll(cx) {
            std::task::Poll::Ready(v) => {
                this.enabled = false;
                std::task::Poll::Ready(v)
            }
            u => u,
        }
    }
}

impl<T: Wait> Wait for SingleshotSleep<T> {
    fn reset(self: Pin<&mut Self>, deadline: tokio::time::Instant) {
        let this = self.get_mut();
        this.enabled = true;
        this.sleep.as_mut().reset(deadline);
    }
}

pub struct DaemonChannels {
    pub config_receiver: tokio::sync::watch::Receiver<CombinedSystemConfig>,
    pub config_sender: tokio::sync::watch::Sender<CombinedSystemConfig>,
    pub peer_snapshots_receiver: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
}

/// Spawn the NTP daemon
pub async fn spawn(
    config: CombinedSystemConfig,
    peer_configs: &[PeerConfig],
    server_configs: &[ServerConfig],
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)> {
    let clock = UnixNtpClock::new();
    let (mut system, channels) = System::new(clock, config);

    for peer_config in peer_configs {
        match peer_config {
            PeerConfig::Standard(cfg) => {
                system.add_spawner(StandardSpawner::new(cfg.clone(), NETWORK_WAIT_PERIOD));
            }
            PeerConfig::Nts(cfg) => {
                system.add_spawner(NtsSpawner::new(cfg.clone(), NETWORK_WAIT_PERIOD));
            }
            PeerConfig::Pool(cfg) => {
                system.add_spawner(PoolSpawner::new(cfg.clone(), NETWORK_WAIT_PERIOD));
            }
        }
    }

    for server_config in server_configs.iter() {
        system.add_server(server_config.to_owned()).await;
    }

    let handle = tokio::spawn(async move {
        let sleep =
            SingleshotSleep::new_disabled(tokio::time::sleep_until(tokio::time::Instant::now()));
        tokio::pin!(sleep);
        system.run(sleep).await
    });

    Ok((handle, channels))
}

struct SystemSpawnerData {
    id: SpawnerId,
    notify_tx: mpsc::Sender<RemovedPeer>,
}

struct System<C: NtpClock, T: Wait> {
    _wait: PhantomData<SingleshotSleep<T>>,
    config: CombinedSystemConfig,
    system: SystemSnapshot,

    config_receiver: tokio::sync::watch::Receiver<CombinedSystemConfig>,
    system_snapshot_sender: tokio::sync::watch::Sender<SystemSnapshot>,
    peer_snapshots_sender: tokio::sync::watch::Sender<Vec<ObservablePeerState>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    spawn_tx: mpsc::Sender<SpawnEvent>,
    spawn_rx: mpsc::Receiver<SpawnEvent>,

    peers: HashMap<PeerIndex, PeerState>,
    servers: Vec<ServerData>,
    spawners: Vec<SystemSpawnerData>,
    peer_indexer: PeerIndexIssuer,

    peer_channels: PeerChannels,

    clock: C,
    controller: DefaultTimeSyncController<C, PeerIndex>,
}

impl<C: NtpClock, T: Wait> System<C, T> {
    const MESSAGE_BUFFER_SIZE: usize = 32;

    fn new(clock: C, config: CombinedSystemConfig) -> (Self, DaemonChannels) {
        // Setup system snapshot
        let system = SystemSnapshot {
            stratum: config.system.local_stratum,
            ..Default::default()
        };

        // Create communication channels
        let (config_sender, config_receiver) = tokio::sync::watch::channel(config);
        let (system_snapshot_sender, system_snapshot_receiver) =
            tokio::sync::watch::channel(system);
        let (peer_snapshots_sender, peer_snapshots_receiver) = tokio::sync::watch::channel(vec![]);
        let (server_data_sender, server_data_receiver) = tokio::sync::watch::channel(vec![]);
        let (msg_for_system_sender, msg_for_system_receiver) =
            tokio::sync::mpsc::channel(Self::MESSAGE_BUFFER_SIZE);
        let (spawn_tx, spawn_rx) = mpsc::channel(Self::MESSAGE_BUFFER_SIZE);

        // Build System and its channels
        (
            System {
                _wait: PhantomData,
                config,
                system,

                config_receiver: config_receiver.clone(),
                system_snapshot_sender,
                peer_snapshots_sender,
                server_data_sender,

                msg_for_system_rx: msg_for_system_receiver,
                spawn_rx,
                spawn_tx,

                peers: Default::default(),
                servers: Default::default(),
                spawners: Default::default(),
                peer_indexer: Default::default(),
                peer_channels: PeerChannels {
                    msg_for_system_sender,
                    system_snapshot_receiver: system_snapshot_receiver.clone(),
                    system_config_receiver: config_receiver.clone(),
                },
                clock: clock.clone(),
                controller: DefaultTimeSyncController::new(clock, config.system, config.algorithm),
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

    fn add_spawner(&mut self, spawner: impl Spawner + Send + Sync + 'static) {
        let (notify_tx, notify_rx) = mpsc::channel(Self::MESSAGE_BUFFER_SIZE);
        let spawner_data = SystemSpawnerData {
            id: spawner.get_id(),
            notify_tx,
        };
        info!(id=?spawner_data.id, addr=spawner.get_addr_description(), "Running spawner");
        self.spawners.push(spawner_data);
        spawner.run(self.spawn_tx.clone(), notify_rx);
    }

    async fn run(&mut self, mut wait: Pin<&mut SingleshotSleep<T>>) -> std::io::Result<()> {
        loop {
            tokio::select! {
                opt_msg_for_system = self.msg_for_system_rx.recv() => {
                    match opt_msg_for_system {
                        None => {
                            // the channel closed and has no more messages in it
                            break
                        }
                        Some(msg_for_system) => {
                            self.handle_peer_update(msg_for_system, &mut wait)
                                .await?;
                        }
                    }
                }
                opt_spawn_event = self.spawn_rx.recv() => {
                    match opt_spawn_event {
                        None => {
                            tracing::warn!("the spawn channel closed unexpectedly");
                        }
                        Some(spawn_event) => {
                            self.handle_spawn_event(spawn_event);
                        }
                    }
                }
                () = &mut wait => {
                    self.handle_timer(&mut wait);
                }
                _ = self.config_receiver.changed(), if self.config_receiver.has_changed().is_ok() => {
                    self.handle_config_update();
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }

    fn handle_config_update(&mut self) {
        let config = *self.config_receiver.borrow_and_update();
        self.controller
            .update_config(config.system, config.algorithm);
        self.config = config;
    }

    fn handle_timer(&mut self, wait: &mut Pin<&mut SingleshotSleep<T>>) {
        tracing::debug!("Timer expired");
        // note: local needed for borrow checker
        let update = self.controller.time_update();
        self.handle_algorithm_state_update(update, wait);
    }

    async fn handle_peer_update(
        &mut self,
        msg: MsgForSystem,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) -> std::io::Result<()> {
        tracing::debug!(?msg, "updating peer");

        match msg {
            MsgForSystem::MustDemobilize(index) => {
                self.handle_peer_demobilize(index).await;
            }
            MsgForSystem::NewMeasurement(index, snapshot, measurement, packet) => {
                self.handle_peer_measurement(index, snapshot, measurement, packet, wait);
            }
            MsgForSystem::UpdatedSnapshot(index, snapshot) => {
                self.handle_peer_snapshot(index, snapshot);
            }
            MsgForSystem::NetworkIssue(index) => {
                self.handle_peer_network_issue(index).await?;
            }
        }

        // Don't care if there is no receiver for peer snapshots (which might happen if
        // we don't enable observing in the configuration)
        let _ = self
            .peer_snapshots_sender
            .send(self.observe_peers().collect());

        Ok(())
    }

    async fn handle_peer_network_issue(&mut self, index: PeerIndex) -> std::io::Result<()> {
        // Restart the peer reusing its configuration.
        let state = self.peers.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let peer_id = state.peer_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(RemovedPeer::new(peer_id, PeerRemovalReason::NetworkIssue))
                .await
                .expect("Could not notify spawner");
        }

        Ok(())
    }

    fn handle_peer_snapshot(&mut self, index: PeerIndex, snapshot: PeerSnapshot) {
        self.controller.peer_update(
            index,
            snapshot
                .accept_synchronization(self.config.system.local_stratum)
                .is_ok(),
        );
        self.peers.get_mut(&index).unwrap().snapshot = Some(snapshot);
    }

    fn handle_peer_measurement(
        &mut self,
        index: PeerIndex,
        snapshot: PeerSnapshot,
        measurement: ntp_proto::Measurement,
        packet: ntp_proto::NtpPacket<'static>,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) {
        self.handle_peer_snapshot(index, snapshot);
        // note: local needed for borrow checker
        let update = self.controller.peer_measurement(index, measurement, packet);
        self.handle_algorithm_state_update(update, wait);
    }

    fn handle_algorithm_state_update(
        &mut self,
        update: ntp_proto::StateUpdate<PeerIndex>,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) {
        if let Some(ref used_peers) = update.used_peers {
            self.system.update_used_peers(used_peers.iter().map(|v| {
                self.peers.get(v).and_then(|data| data.snapshot).expect(
                    "Critical error: Peer used for synchronization that is not known to system",
                )
            }));
        }
        if let Some(time_snapshot) = update.time_snapshot {
            self.system
                .update_timedata(time_snapshot, &self.config.system);
        }
        if let Some(timestamp) = update.next_update {
            let duration = timestamp - self.clock.now().expect("Could not get current time");
            let duration =
                std::time::Duration::from_secs_f64(duration.max(NtpDuration::ZERO).to_seconds());
            wait.as_mut().reset(tokio::time::Instant::now() + duration);
        }
        if update.used_peers.is_some() || update.time_snapshot.is_some() {
            // Don't care if there is no receiver.
            let _ = self.system_snapshot_sender.send(self.system);
        }
    }

    async fn handle_peer_demobilize(&mut self, index: PeerIndex) {
        self.controller.peer_remove(index);
        let state = self.peers.remove(&index).unwrap();

        // Restart the peer reusing its configuration.
        let spawner_id = state.spawner_id;
        let peer_id = state.peer_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(RemovedPeer::new(peer_id, PeerRemovalReason::Demobilized))
                .await
                .expect("Could not notify spawner");
        }
    }

    fn handle_spawn_event(&mut self, event: SpawnEvent) {
        match event.action {
            SpawnAction::Create(peer_id, addr, peer_address, nts_data) => {
                info!(?peer_id, ?addr, spawner=?event.id, "new peer");
                let index = self.peer_indexer.get();
                self.peers.insert(
                    index,
                    PeerState {
                        snapshot: None,
                        peer_address,
                        peer_id,
                        spawner_id: event.id,
                    },
                );
                self.controller.peer_add(index);

                PeerTask::spawn(
                    index,
                    addr,
                    self.clock.clone(),
                    NETWORK_WAIT_PERIOD,
                    self.peer_channels.clone(),
                    nts_data,
                );

                // Don't care if there is not receiver
                let _ = self
                    .peer_snapshots_sender
                    .send(self.observe_peers().collect());
            }
        }
    }

    /// Adds up to `max_peers` peers from a pool.
    #[cfg(test)]
    async fn add_new_pool(&mut self, address: NormalizedAddress, max_peers: usize) {
        self.add_spawner(PoolSpawner::new(
            crate::config::PoolPeerConfig {
                addr: address,
                max_peers,
            },
            NETWORK_WAIT_PERIOD,
        ));
    }

    /// Adds a single peer (that is not part of a pool!)
    #[cfg(test)]
    async fn add_peer(&mut self, address: NormalizedAddress) {
        self.add_spawner(StandardSpawner::new(
            crate::config::StandardPeerConfig { addr: address },
            NETWORK_WAIT_PERIOD,
        ));
    }

    /// Adds a single NTS peer
    #[cfg(test)]
    async fn add_nts_peer(
        &mut self,
        ke_addr: NormalizedAddress,
        certificates: std::sync::Arc<[rustls::Certificate]>,
    ) {
        self.add_spawner(NtsSpawner::new(
            crate::config::NtsPeerConfig {
                ke_addr,
                certificates,
            },
            NETWORK_WAIT_PERIOD,
        ));
    }

    async fn add_server(&mut self, config: ServerConfig) {
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
        );
        let _ = self.server_data_sender.send(self.servers.clone());
    }

    fn observe_peers(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(index, data)| {
            data.snapshot
                .map(|snapshot| {
                    if let Some(timedata) = self.controller.peer_snapshot(*index) {
                        ObservablePeerState::Observable {
                            timedata,
                            reachability: snapshot.reach,
                            poll_interval: snapshot.poll_interval,
                            peer_id: snapshot.peer_id,
                            address: data.peer_address.to_string(),
                        }
                    } else {
                        ObservablePeerState::Nothing
                    }
                })
                .unwrap_or(ObservablePeerState::Nothing)
        })
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

#[derive(Debug)]
struct PeerState {
    snapshot: Option<PeerSnapshot>,
    peer_address: NormalizedAddress,
    spawner_id: SpawnerId,
    peer_id: PeerId,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}

#[cfg(test)]
mod tests {
    use ntp_proto::{
        peer_snapshot, Measurement, NtpDuration, NtpInstant, NtpLeapIndicator, NtpPacket,
        NtpTimestamp, PollInterval,
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

        fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
            Ok(NtpTimestamp::default())
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
            Ok(NtpTimestamp::default())
        }

        fn enable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn ntp_algorithm_update(
            &self,
            _offset: NtpDuration,
            _poll_interval: PollInterval,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn error_estimate_update(
            &self,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn handle_spawn_no_nts<C: NtpClock, T: Wait>(
        system: &mut System<C, T>,
        peer_address: PeerAddress,
        addr: SocketAddr,
    ) {
        system.handle_spawn(peer_address, addr, None)
    }

    #[tokio::test]
    async fn test_peers() {
        let (mut system, _) = System::new(TestClock {}, CombinedSystemConfig::default());
        let wait =
            SingleshotSleep::new_disabled(tokio::time::sleep(std::time::Duration::from_secs(0)));
        tokio::pin!(wait);

        let mut indices = [PeerIndex { index: 0 }; 4];

        for (i, item) in indices.iter_mut().enumerate() {
            *item = system.create_test_peer(NormalizedAddress::new_unchecked(
                &format!("127.0.0.{i}",),
                123,
            ));
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
            .handle_peer_update(
                MsgForSystem::NewMeasurement(
                    indices[0],
                    peer_snapshot(),
                    Measurement {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                        monotime: base,
                    },
                    NtpPacket::test(),
                ),
                &mut wait,
            )
            .await
            .unwrap();
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
            .handle_peer_update(
                MsgForSystem::NewMeasurement(
                    indices[0],
                    peer_snapshot(),
                    Measurement {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                        monotime: base,
                    },
                    NtpPacket::test(),
                ),
                &mut wait,
            )
            .await
            .unwrap();
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
            .handle_peer_update(
                MsgForSystem::UpdatedSnapshot(indices[1], peer_snapshot()),
                &mut wait,
            )
            .await
            .unwrap();
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
            .handle_peer_update(MsgForSystem::MustDemobilize(indices[1]), &mut wait)
            .await
            .unwrap();
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
        let (mut system, _) = System::new(TestClock {}, CombinedSystemConfig::default());
        let wait =
            SingleshotSleep::new_disabled(tokio::time::sleep(std::time::Duration::from_secs(0)));
        tokio::pin!(wait);

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.2", 123);
        system.add_standard_peer(peer_address).await;

        let pool_address = NormalizedAddress::new_unchecked("127.0.0.1", 123);
        let max_peers = 1;
        system.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            handle_spawn_no_nts(&mut system, task.peer_address, task.address);
        }

        // we have 2 peers
        assert_eq!(system.peers.len(), 2);

        // our pool peer has a network issue
        system
            .handle_peer_update(
                MsgForSystem::NetworkIssue(PeerIndex { index: 1 }),
                &mut wait,
            )
            .await
            .unwrap();

        for _ in 0..1 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            handle_spawn_no_nts(&mut system, task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 2);
    }

    #[tokio::test]
    async fn max_peers_bigger_than_pool_size() {
        let (mut system, _) = System::new(TestClock {}, CombinedSystemConfig::default());
        let wait =
            SingleshotSleep::new_disabled(tokio::time::sleep(std::time::Duration::from_secs(0)));
        tokio::pin!(wait);

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5", 123);
        system.add_standard_peer(peer_address).await;

        let pool_address = NormalizedAddress::with_hardcoded_dns(
            "tweedegolf.nl",
            123,
            vec!["127.0.0.1:123".parse().unwrap()],
        );
        let max_peers = 2;
        system.add_new_pool(pool_address.clone(), max_peers).await;

        for _ in 0..2 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            handle_spawn_no_nts(&mut system, task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(system.peers.len(), 2);

        dbg!("initial spawns completed");

        // our pool peer has a network issue
        system
            .handle_peer_update(
                MsgForSystem::NetworkIssue(PeerIndex { index: 1 }),
                &mut wait,
            )
            .await
            .unwrap();

        for _ in 0..1 {
            let task = system.spawn_task_rx.recv().await.unwrap();
            handle_spawn_no_nts(&mut system, task.peer_address, task.address);
        }

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 2);
    }

    #[tokio::test]
    async fn simulate_pool() {
        let (mut system, _) = System::new(TestClock {}, CombinedSystemConfig::default());
        let wait =
            SingleshotSleep::new_disabled(tokio::time::sleep(std::time::Duration::from_secs(0)));
        tokio::pin!(wait);

        let peer_address = NormalizedAddress::new_unchecked("127.0.0.5", 123);
        system.add_standard_peer(peer_address).await;

        let pool_address = NormalizedAddress::with_hardcoded_dns(
            "tweedegolf.nl",
            123,
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
            handle_spawn_no_nts(&mut system, task.peer_address, task.address);
        }

        // we have only 2 peers, because the pool has size 1
        assert_eq!(system.peers.len(), 4);

        // simulate that a pool peer has a network issue
        system
            .handle_peer_update(
                MsgForSystem::NetworkIssue(PeerIndex { index: 1 }),
                &mut wait,
            )
            .await
            .unwrap();

        let task = system.spawn_task_rx.recv().await.unwrap();
        handle_spawn_no_nts(&mut system, task.peer_address, task.address);

        // automatically selects another peer from the pool
        assert_eq!(system.peers.len(), 4);
    }
}
