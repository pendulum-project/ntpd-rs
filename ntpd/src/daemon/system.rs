use super::{
    config::{
        ClockConfig, CombinedSynchronizationConfig, NormalizedAddress, PeerConfig, ServerConfig,
    },
    peer::{MsgForSystem, PeerChannels},
    peer::{PeerTask, Wait},
    server::{ServerStats, ServerTask},
    spawn::{
        nts::NtsSpawner, pool::PoolSpawner, standard::StandardSpawner, PeerCreateParameters,
        PeerId, PeerRemovalReason, SpawnAction, SpawnEvent, Spawner, SpawnerId, SystemEvent,
    },
    ObservablePeerState, ObservedPeerState,
};

use std::{collections::HashMap, future::Future, marker::PhantomData, pin::Pin, sync::Arc};

use ntp_proto::{
    DefaultTimeSyncController, KeySet, NtpClock, NtpDuration, PeerSnapshot, SourceDefaultsConfig,
    SystemSnapshot, TimeSyncController,
};
use ntp_udp::{EnableTimestamps, InterfaceName};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, info};

pub const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

pub const MESSAGE_BUFFER_SIZE: usize = 32;

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
    pub synchronization_config_receiver:
        tokio::sync::watch::Receiver<CombinedSynchronizationConfig>,
    pub synchronization_config_sender: tokio::sync::watch::Sender<CombinedSynchronizationConfig>,
    pub peer_defaults_config_receiver: tokio::sync::watch::Receiver<SourceDefaultsConfig>,
    pub peer_defaults_config_sender: tokio::sync::watch::Sender<SourceDefaultsConfig>,
    pub peer_snapshots_receiver: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
    pub keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
}

/// Spawn the NTP daemon
pub async fn spawn(
    synchronization_config: CombinedSynchronizationConfig,
    peer_defaults_config: SourceDefaultsConfig,
    clock_config: ClockConfig,
    peer_configs: &[PeerConfig],
    server_configs: &[ServerConfig],
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)> {
    let (mut system, channels) = System::new(
        clock_config.clock,
        clock_config.interface,
        clock_config.enable_timestamps,
        synchronization_config,
        peer_defaults_config,
        keyset,
    );

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
    notify_tx: mpsc::Sender<SystemEvent>,
}

struct System<C: NtpClock, T: Wait> {
    _wait: PhantomData<SingleshotSleep<T>>,
    synchronization_config: CombinedSynchronizationConfig,
    peer_defaults_config: SourceDefaultsConfig,
    system: SystemSnapshot,

    synchronization_config_receiver: tokio::sync::watch::Receiver<CombinedSynchronizationConfig>,
    peer_defaults_config_receiver: tokio::sync::watch::Receiver<SourceDefaultsConfig>,
    system_snapshot_sender: tokio::sync::watch::Sender<SystemSnapshot>,
    peer_snapshots_sender: tokio::sync::watch::Sender<Vec<ObservablePeerState>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    spawn_tx: mpsc::Sender<SpawnEvent>,
    spawn_rx: mpsc::Receiver<SpawnEvent>,

    peers: HashMap<PeerId, PeerState>,
    servers: Vec<ServerData>,
    spawners: Vec<SystemSpawnerData>,

    peer_channels: PeerChannels,

    clock: C,
    controller: DefaultTimeSyncController<C, PeerId>,

    // which timestamps to use (this is a hint, OS or hardware may ignore)
    enable_timestamps: EnableTimestamps,

    // bind the socket to a specific interface. This is relevant for hardware timestamping,
    // because the interface determines which clock is used to produce the timestamps.
    interface: Option<InterfaceName>,
}

impl<C: NtpClock, T: Wait> System<C, T> {
    fn new(
        clock: C,
        interface: Option<InterfaceName>,
        enable_timestamps: EnableTimestamps,
        synchronization_config: CombinedSynchronizationConfig,
        peer_defaults_config: SourceDefaultsConfig,
        keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    ) -> (Self, DaemonChannels) {
        // Setup system snapshot
        let system = SystemSnapshot {
            stratum: synchronization_config.synchronization.local_stratum,
            ..Default::default()
        };

        // Create communication channels
        let (synchronization_config_sender, synchronization_config_receiver) =
            tokio::sync::watch::channel(synchronization_config);
        let (peer_defaults_config_sender, peer_defaults_config_receiver) =
            tokio::sync::watch::channel(peer_defaults_config);
        let (system_snapshot_sender, system_snapshot_receiver) =
            tokio::sync::watch::channel(system);
        let (peer_snapshots_sender, peer_snapshots_receiver) = tokio::sync::watch::channel(vec![]);
        let (server_data_sender, server_data_receiver) = tokio::sync::watch::channel(vec![]);
        let (msg_for_system_sender, msg_for_system_receiver) =
            tokio::sync::mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (spawn_tx, spawn_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Build System and its channels
        (
            System {
                _wait: PhantomData,
                synchronization_config,
                peer_defaults_config,
                system,

                synchronization_config_receiver: synchronization_config_receiver.clone(),
                peer_defaults_config_receiver: peer_defaults_config_receiver.clone(),
                system_snapshot_sender,
                peer_snapshots_sender,
                server_data_sender,
                keyset: keyset.clone(),

                msg_for_system_rx: msg_for_system_receiver,
                spawn_rx,
                spawn_tx,

                peers: Default::default(),
                servers: Default::default(),
                spawners: Default::default(),
                peer_channels: PeerChannels {
                    msg_for_system_sender,
                    system_snapshot_receiver: system_snapshot_receiver.clone(),
                    synchronization_config_receiver: synchronization_config_receiver.clone(),
                    source_defaults_config_receiver: peer_defaults_config_receiver.clone(),
                },
                clock: clock.clone(),
                controller: DefaultTimeSyncController::new(
                    clock,
                    synchronization_config.synchronization,
                    peer_defaults_config,
                    synchronization_config.algorithm,
                ),
                enable_timestamps,
                interface,
            },
            DaemonChannels {
                synchronization_config_receiver,
                synchronization_config_sender,
                peer_defaults_config_receiver,
                peer_defaults_config_sender,
                peer_snapshots_receiver,
                server_data_receiver,
                system_snapshot_receiver,
                keyset,
            },
        )
    }

    fn add_spawner(&mut self, spawner: impl Spawner + Send + Sync + 'static) -> SpawnerId {
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let id = spawner.get_id();
        let spawner_data = SystemSpawnerData { id, notify_tx };
        debug!(id=?spawner_data.id, ty=spawner.get_description(), addr=spawner.get_addr_description(), "Running spawner");
        self.spawners.push(spawner_data);
        let spawn_tx = self.spawn_tx.clone();
        tokio::spawn(async move { spawner.run(spawn_tx, notify_rx).await });
        id
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
                            let msg = "the spawn channel closed unexpectedly. ntpd-rs is likely in an invalid state!";
                            tracing::warn!(msg);
                        }
                        Some(spawn_event) => {
                            self.handle_spawn_event(spawn_event).await;
                        }
                    }
                }
                () = &mut wait => {
                    self.handle_timer(&mut wait);
                }
                _ = self.synchronization_config_receiver.changed(), if self.synchronization_config_receiver.has_changed().is_ok() => {
                    self.handle_config_update();
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }

    fn handle_config_update(&mut self) {
        let synchronization_config = *self.synchronization_config_receiver.borrow_and_update();
        let peer_defaults_config = *self.peer_defaults_config_receiver.borrow_and_update();
        self.controller.update_config(
            synchronization_config.synchronization,
            peer_defaults_config,
            synchronization_config.algorithm,
        );
        self.synchronization_config = synchronization_config;
        self.peer_defaults_config = peer_defaults_config;
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
            MsgForSystem::NewMeasurement(index, snapshot, measurement) => {
                self.handle_peer_measurement(index, snapshot, measurement, wait);
            }
            MsgForSystem::UpdatedSnapshot(index, snapshot) => {
                self.handle_peer_snapshot(index, snapshot);
            }
            MsgForSystem::NetworkIssue(index) => {
                self.handle_peer_network_issue(index).await?;
            }
            MsgForSystem::Unreachable(index) => {
                self.handle_peer_unreachable(index).await?;
            }
        }

        // Don't care if there is no receiver for peer snapshots (which might happen if
        // we don't enable observing in the configuration)
        let _ = self
            .peer_snapshots_sender
            .send(self.observe_peers().collect());

        Ok(())
    }

    async fn handle_peer_network_issue(&mut self, index: PeerId) -> std::io::Result<()> {
        self.controller.peer_remove(index);

        // Restart the peer reusing its configuration.
        let state = self.peers.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::peer_removed(
                    source_id,
                    PeerRemovalReason::NetworkIssue,
                ))
                .await
                .expect("Could not notify spawner");
        }

        Ok(())
    }

    async fn handle_peer_unreachable(&mut self, index: PeerId) -> std::io::Result<()> {
        self.controller.peer_remove(index);

        // Restart the peer reusing its configuration.
        let state = self.peers.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::peer_removed(
                    source_id,
                    PeerRemovalReason::Unreachable,
                ))
                .await
                .expect("Could not notify spawner");
        }

        Ok(())
    }

    fn handle_peer_snapshot(&mut self, index: PeerId, snapshot: PeerSnapshot) {
        self.controller.peer_update(
            index,
            snapshot
                .accept_synchronization(self.synchronization_config.synchronization.local_stratum)
                .is_ok(),
        );
        self.peers.get_mut(&index).unwrap().snapshot = Some(snapshot);
    }

    fn handle_peer_measurement(
        &mut self,
        index: PeerId,
        snapshot: PeerSnapshot,
        measurement: ntp_proto::Measurement,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) {
        self.handle_peer_snapshot(index, snapshot);
        // note: local needed for borrow checker
        let update = self.controller.peer_measurement(index, measurement);
        self.handle_algorithm_state_update(update, wait);
    }

    fn handle_algorithm_state_update(
        &mut self,
        update: ntp_proto::StateUpdate<PeerId>,
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
                .update_timedata(time_snapshot, &self.synchronization_config.synchronization);
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

    async fn handle_peer_demobilize(&mut self, index: PeerId) {
        self.controller.peer_remove(index);
        let state = self.peers.remove(&index).unwrap();

        // Restart the peer reusing its configuration.
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::peer_removed(
                    source_id,
                    PeerRemovalReason::Demobilized,
                ))
                .await
                .expect("Could not notify spawner");
        }
    }

    async fn create_peer(
        &mut self,
        spawner_id: SpawnerId,
        mut params: PeerCreateParameters,
    ) -> PeerId {
        let source_id = params.id;
        info!(source_id=?source_id, addr=?params.addr, spawner=?spawner_id, "new peer");
        self.peers.insert(
            source_id,
            PeerState {
                snapshot: None,
                peer_address: params.normalized_addr.clone(),
                source_id,
                spawner_id,
            },
        );
        self.controller.peer_add(source_id);

        PeerTask::spawn(
            source_id,
            params.addr,
            self.interface,
            self.clock.clone(),
            self.enable_timestamps,
            NETWORK_WAIT_PERIOD,
            self.peer_channels.clone(),
            params.nts.take(),
        );

        // Don't care if there is no receiver
        let _ = self
            .peer_snapshots_sender
            .send(self.observe_peers().collect());

        // Try and find a related spawner and notify that spawner.
        // This makes sure that the spawner that initially sent the create event
        // is now aware that the peer was added to the system.
        if let Some(s) = self.spawners.iter().find(|s| s.id == spawner_id) {
            let _ = s.notify_tx.send(SystemEvent::PeerRegistered(params)).await;
        }

        source_id
    }

    async fn handle_spawn_event(&mut self, event: SpawnEvent) {
        match event.action {
            SpawnAction::Create(params) => {
                self.create_peer(event.id, params).await;
            }
        }
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
            self.keyset.clone(),
            self.clock.clone(),
            self.interface,
            NETWORK_WAIT_PERIOD,
        );
        let _ = self.server_data_sender.send(self.servers.clone());
    }

    fn observe_peers(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(index, data)| {
            data.snapshot
                .map(|snapshot| {
                    if let Some(timedata) = self.controller.peer_snapshot(*index) {
                        ObservablePeerState::Observable(ObservedPeerState {
                            timedata,
                            unanswered_polls: snapshot.reach.unanswered_polls(),
                            poll_interval: snapshot.poll_interval,
                            address: data.peer_address.to_string(),
                            id: data.source_id,
                        })
                    } else {
                        ObservablePeerState::Nothing
                    }
                })
                .unwrap_or(ObservablePeerState::Nothing)
        })
    }
}

#[derive(Debug)]
struct PeerState {
    snapshot: Option<PeerSnapshot>,
    peer_address: NormalizedAddress,
    spawner_id: SpawnerId,
    source_id: PeerId,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}

#[cfg(test)]
mod tests {
    use ntp_proto::{
        peer_snapshot, KeySetProvider, Measurement, NtpDuration, NtpInstant, NtpLeapIndicator,
        NtpTimestamp, PollInterval,
    };

    use super::super::spawn::dummy::DummySpawner;

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

    #[tokio::test]
    async fn test_peers() {
        // we always generate the keyset (even if NTS is not used)
        let (_, keyset) = tokio::sync::watch::channel(KeySetProvider::new(1).get());

        let (mut system, _) = System::new(
            TestClock {},
            InterfaceName::DEFAULT,
            EnableTimestamps::default(),
            CombinedSynchronizationConfig::default(),
            SourceDefaultsConfig::default(),
            keyset,
        );
        let wait =
            SingleshotSleep::new_disabled(tokio::time::sleep(std::time::Duration::from_secs(0)));
        tokio::pin!(wait);

        let id = system.add_spawner(DummySpawner::empty());

        let mut indices = vec![];

        for i in 0..4 {
            indices.push(
                system
                    .create_peer(
                        id,
                        PeerCreateParameters::from_new_ip_and_port(format!("127.0.0.{i}"), 123),
                    )
                    .await,
            );
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
                        transmit_timestamp: NtpTimestamp::default(),
                        receive_timestamp: NtpTimestamp::default(),
                        localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                        monotime: base,

                        stratum: 0,
                        root_delay: NtpDuration::default(),
                        root_dispersion: NtpDuration::default(),
                        leap: NtpLeapIndicator::NoWarning,
                        precision: 0,
                    },
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
                        transmit_timestamp: NtpTimestamp::default(),
                        receive_timestamp: NtpTimestamp::default(),
                        localtime: NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0),
                        monotime: base,

                        stratum: 0,
                        root_delay: NtpDuration::default(),
                        root_dispersion: NtpDuration::default(),
                        leap: NtpLeapIndicator::NoWarning,
                        precision: 0,
                    },
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
}
