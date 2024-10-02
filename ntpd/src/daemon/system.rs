use crate::daemon::{
    sock_source::SockSourceTask,
    spawn::{spawner_task, SourceCreateParameters},
};

#[cfg(feature = "unstable_nts-pool")]
use super::spawn::nts_pool::NtsPoolSpawner;
use super::{
    clock::NtpClockWrapper,
    config::{ClockConfig, NtpSourceConfig, ServerConfig, TimestampMode},
    ntp_source::{MsgForSystem, SourceChannels, SourceTask, Wait},
    server::{ServerStats, ServerTask},
    spawn::{
        nts::NtsSpawner, pool::PoolSpawner, sock::SockSpawner, standard::StandardSpawner, SourceId,
        SourceRemovalReason, SpawnAction, SpawnEvent, Spawner, SpawnerId, SystemEvent,
    },
};

use std::{
    collections::HashMap,
    future::Future,
    marker::PhantomData,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, RwLock},
};

use ntp_proto::{
    KeySet, MeasurementNoiseEstimator, NtpClock, ObservableSourceState, SourceDefaultsConfig,
    SynchronizationConfig, System, SystemActionIterator, SystemSnapshot, SystemSourceUpdate,
    TimeSyncController,
};
use timestamped_socket::interface::InterfaceName;
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
    pub source_snapshots:
        Arc<std::sync::RwLock<HashMap<SourceId, ObservableSourceState<SourceId>>>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
}

/// Spawn the NTP daemon
pub async fn spawn<Controller: TimeSyncController<Clock = NtpClockWrapper, SourceId = SourceId>>(
    synchronization_config: SynchronizationConfig,
    algorithm_config: Controller::AlgorithmConfig,
    source_defaults_config: SourceDefaultsConfig,
    clock_config: ClockConfig,
    source_configs: &[NtpSourceConfig],
    server_configs: &[ServerConfig],
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)> {
    let ip_list = super::local_ip_provider::spawn()?;

    let (mut system, channels) = SystemTask::<_, Controller, _>::new(
        clock_config.clock,
        clock_config.interface,
        clock_config.timestamp_mode,
        synchronization_config,
        algorithm_config,
        source_defaults_config,
        keyset,
        ip_list,
        !source_configs.is_empty(),
    );

    for source_config in source_configs {
        match source_config {
            NtpSourceConfig::Standard(cfg) => {
                system
                    .add_spawner(StandardSpawner::new(cfg.clone()))
                    .map_err(|e| {
                        tracing::error!("Could not spawn source: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?;
            }
            NtpSourceConfig::Nts(cfg) => {
                system
                    .add_spawner(NtsSpawner::new(cfg.clone()))
                    .map_err(|e| {
                        tracing::error!("Could not spawn source: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?;
            }
            NtpSourceConfig::Pool(cfg) => {
                system
                    .add_spawner(PoolSpawner::new(cfg.clone()))
                    .map_err(|e| {
                        tracing::error!("Could not spawn source: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?;
            }
            #[cfg(feature = "unstable_nts-pool")]
            NtpSourceConfig::NtsPool(cfg) => {
                system
                    .add_spawner(NtsPoolSpawner::new(cfg.clone()))
                    .map_err(|e| {
                        tracing::error!("Could not spawn source: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?;
            }
            NtpSourceConfig::Sock(cfg) => {
                system
                    .add_spawner(SockSpawner::new(cfg.clone()))
                    .map_err(|e| {
                        tracing::error!("Could not spawn source: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?;
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

struct SystemTask<
    C: NtpClock,
    Controller: TimeSyncController<SourceId = SourceId, Clock = C>,
    T: Wait,
> {
    _wait: PhantomData<SingleshotSleep<T>>,
    system: System<SourceId, Controller>,

    system_snapshot_sender: tokio::sync::watch::Sender<SystemSnapshot>,
    system_update_sender:
        tokio::sync::broadcast::Sender<SystemSourceUpdate<Controller::ControllerMessage>>,
    source_snapshots: Arc<std::sync::RwLock<HashMap<SourceId, ObservableSourceState<SourceId>>>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    ip_list: tokio::sync::watch::Receiver<Arc<[IpAddr]>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem<Controller::SourceMessage>>,
    msg_for_system_tx: mpsc::Sender<MsgForSystem<Controller::SourceMessage>>,
    spawn_tx: mpsc::Sender<SpawnEvent>,
    spawn_rx: mpsc::Receiver<SpawnEvent>,

    sources: HashMap<SourceId, SourceState>,
    servers: Vec<ServerData>,
    spawners: Vec<SystemSpawnerData>,

    clock: C,

    // which timestamps to use (this is a hint, OS or hardware may ignore)
    timestamp_mode: TimestampMode,

    // bind the socket to a specific interface. This is relevant for hardware timestamping,
    // because the interface determines which clock is used to produce the timestamps.
    interface: Option<InterfaceName>,
}

impl<
        C: NtpClock + Sync,
        Controller: TimeSyncController<Clock = C, SourceId = SourceId>,
        T: Wait,
    > SystemTask<C, Controller, T>
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        clock: C,
        interface: Option<InterfaceName>,
        timestamp_mode: TimestampMode,
        synchronization_config: SynchronizationConfig,
        algorithm_config: Controller::AlgorithmConfig,
        source_defaults_config: SourceDefaultsConfig,
        keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
        ip_list: tokio::sync::watch::Receiver<Arc<[IpAddr]>>,
        have_sources: bool,
    ) -> (Self, DaemonChannels) {
        let Ok(mut system) = System::new(
            clock.clone(),
            synchronization_config,
            source_defaults_config,
            algorithm_config,
            ip_list.borrow().clone(),
        ) else {
            tracing::error!("Could not start system");
            std::process::exit(70);
        };

        if have_sources {
            if let Err(e) = system.check_clock_access() {
                tracing::error!("Could not control clock: {}", e);
                std::process::exit(70);
            }
        }

        // Create communication channels
        let (system_snapshot_sender, system_snapshot_receiver) =
            tokio::sync::watch::channel(system.system_snapshot());
        let source_snapshots = Arc::new(RwLock::new(HashMap::new()));
        let (server_data_sender, server_data_receiver) = tokio::sync::watch::channel(vec![]);
        let (msg_for_system_sender, msg_for_system_receiver) =
            tokio::sync::mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (system_update_sender, _) = tokio::sync::broadcast::channel(MESSAGE_BUFFER_SIZE);
        let (spawn_tx, spawn_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Build System and its channels
        (
            SystemTask {
                _wait: PhantomData,
                system,

                system_snapshot_sender,
                system_update_sender,
                source_snapshots: source_snapshots.clone(),
                server_data_sender,
                keyset: keyset.clone(),
                ip_list,

                msg_for_system_rx: msg_for_system_receiver,
                msg_for_system_tx: msg_for_system_sender,
                spawn_rx,
                spawn_tx,

                sources: Default::default(),
                servers: Default::default(),
                spawners: Default::default(),
                clock,
                timestamp_mode,
                interface,
            },
            DaemonChannels {
                source_snapshots,
                server_data_receiver,
                system_snapshot_receiver,
            },
        )
    }

    fn add_spawner(
        &mut self,
        spawner: impl Spawner + Send + Sync + 'static,
    ) -> Result<SpawnerId, C::Error> {
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let id = spawner.get_id();
        let spawner_data = SystemSpawnerData { id, notify_tx };
        debug!(id=?spawner_data.id, ty=spawner.get_description(), addr=spawner.get_addr_description(), "Running spawner");
        self.spawners.push(spawner_data);
        let spawn_tx = self.spawn_tx.clone();
        // tokio::spawn(async move { spawner.run(spawn_tx, notify_rx).await });
        tokio::spawn(spawner_task(spawner, spawn_tx, notify_rx));
        Ok(id)
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
                            self.handle_source_update(msg_for_system, &mut wait)
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
                            if let Err(e) = self.handle_spawn_event(spawn_event).await {
                                tracing::error!("Could not spawn source: {}", e);
                            }
                        }
                    }
                }
                _ = self.ip_list.changed(), if self.ip_list.has_changed().is_ok() => {
                    self.system.update_ip_list(self.ip_list.borrow_and_update().clone());
                }
                () = &mut wait => {
                    let timer = self.system.handle_timer();
                    self.handle_state_update(timer, &mut wait);
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }

    fn handle_state_update(
        &mut self,
        actions: SystemActionIterator<Controller::ControllerMessage>,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) {
        // Don't care if there is no receiver.
        let _ = self
            .system_snapshot_sender
            .send(self.system.system_snapshot());

        for action in actions {
            match action {
                ntp_proto::SystemAction::UpdateSources(update) => {
                    let _ = self.system_update_sender.send(update);
                }
                ntp_proto::SystemAction::SetTimer(duration) => {
                    wait.as_mut().reset(tokio::time::Instant::now() + duration)
                }
            }
        }
    }

    async fn handle_source_update(
        &mut self,
        msg: MsgForSystem<Controller::SourceMessage>,
        wait: &mut Pin<&mut SingleshotSleep<T>>,
    ) -> std::io::Result<()> {
        tracing::debug!(?msg, "updating source");

        match msg {
            MsgForSystem::MustDemobilize(index) => {
                if let Err(e) = self.handle_source_demobilize(index).await {
                    unreachable!("Could not demobilize source: {}", e);
                };
            }
            MsgForSystem::SourceUpdate(index, update) => {
                match self.system.handle_source_update(index, update) {
                    Err(e) => unreachable!("Could not process source measurement: {}", e),
                    Ok(timer) => self.handle_state_update(timer, wait),
                }
            }
            MsgForSystem::NetworkIssue(index) => {
                self.handle_source_network_issue(index).await?;
            }
            MsgForSystem::Unreachable(index) => {
                self.handle_source_unreachable(index).await?;
            }
        }

        Ok(())
    }

    async fn handle_source_network_issue(&mut self, index: SourceId) -> std::io::Result<()> {
        self.system
            .handle_source_remove(index)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Restart the source reusing its configuration.
        let state = self.sources.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::source_removed(
                    source_id,
                    SourceRemovalReason::NetworkIssue,
                ))
                .await
                .expect("Could not notify spawner");
        }

        Ok(())
    }

    async fn handle_source_unreachable(&mut self, index: SourceId) -> std::io::Result<()> {
        self.system
            .handle_source_remove(index)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Restart the source reusing its configuration.
        let state = self.sources.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::source_removed(
                    source_id,
                    SourceRemovalReason::Unreachable,
                ))
                .await
                .expect("Could not notify spawner");
        }

        Ok(())
    }

    async fn handle_source_demobilize(&mut self, index: SourceId) -> Result<(), C::Error> {
        self.system.handle_source_remove(index)?;

        // Restart the source reusing its configuration.
        let state = self.sources.remove(&index).unwrap();
        let spawner_id = state.spawner_id;
        let source_id = state.source_id;
        let opt_spawner = self.spawners.iter().find(|s| s.id == spawner_id);
        if let Some(spawner) = opt_spawner {
            spawner
                .notify_tx
                .send(SystemEvent::source_removed(
                    source_id,
                    SourceRemovalReason::Demobilized,
                ))
                .await
                .expect("Could not notify spawner");
        }
        Ok(())
    }

    async fn create_source(
        &mut self,
        spawner_id: SpawnerId,
        mut params: SourceCreateParameters,
    ) -> Result<SourceId, C::Error> {
        let source_id = params.get_id();
        info!(source_id=?source_id, addr=?params.get_addr(), spawner=?spawner_id, "new source");
        self.sources.insert(
            source_id,
            SourceState {
                source_id,
                spawner_id,
            },
        );

        match params {
            SourceCreateParameters::Ntp(ref mut params) => {
                let (source, initial_actions) = self.system.create_ntp_source(
                    source_id,
                    params.addr,
                    params.protocol_version,
                    params.nts.take(),
                )?;

                SourceTask::spawn(
                    source_id,
                    params.normalized_addr.to_string(),
                    params.addr,
                    self.interface,
                    self.clock.clone(),
                    self.timestamp_mode,
                    SourceChannels {
                        msg_for_system_sender: self.msg_for_system_tx.clone(),
                        system_update_receiver: self.system_update_sender.subscribe(),
                        source_snapshots: self.source_snapshots.clone(),
                    },
                    source,
                    initial_actions,
                );
            }
            SourceCreateParameters::Sock(ref params) => {
                SockSourceTask::spawn(
                    params.path.clone(),
                    self.clock.clone(),
                    self.system.create_source_controller(
                        source_id,
                        MeasurementNoiseEstimator::Constant(params.noise_estimate),
                    )?,
                );
            }
        };

        // Try and find a related spawner and notify that spawner.
        // This makes sure that the spawner that initially sent the create event
        // is now aware that the source was added to the system.
        if let Some(s) = self.spawners.iter().find(|s| s.id == spawner_id) {
            let _ = s
                .notify_tx
                .send(SystemEvent::SourceRegistered(params))
                .await;
        }

        Ok(source_id)
    }

    async fn handle_spawn_event(&mut self, event: SpawnEvent) -> Result<(), C::Error> {
        match event.action {
            SpawnAction::Create(params) => {
                self.create_source(event.id, params).await?;
            }
        }
        Ok(())
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
            self.system_snapshot_sender.subscribe(),
            self.keyset.clone(),
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
        );
        let _ = self.server_data_sender.send(self.servers.clone());
    }
}

#[derive(Debug)]
struct SourceState {
    spawner_id: SpawnerId,
    source_id: SourceId,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}
