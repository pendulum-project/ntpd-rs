#[cfg(target_os = "linux")]
use crate::daemon::config::CsptpConfig;
#[cfg(feature = "pps")]
use crate::daemon::pps_source::PpsSourceTask;
use crate::daemon::{
    sock_source::SockSourceTask,
    spawn::{SourceCreateParameters, spawner_task},
};

use super::spawn::nts_pool::NtsPoolSpawner;
use super::{
    clock::NtpClockWrapper,
    config::{ClockConfig, NtpSourceConfig, ServerConfig, TimestampMode},
    ntp_source::{MsgForSystem, SourceChannels, SourceTask},
    server::{ServerStats, ServerTask},
    spawn::{
        SourceRemovalReason, SpawnAction, SpawnEvent, Spawner, SpawnerId, SystemEvent,
        nts::NtsSpawner, pool::PoolSpawner, sock::SockSpawner, standard::StandardSpawner,
    },
};

#[cfg(feature = "pps")]
use super::spawn::pps::PpsSpawner;

#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
};

use ntp_proto::{
    ClockId, KeySet, NtpClock, NtpManager, ObservableSourceState, PollIntervalLimits, SourceConfig,
    SourceType, StatimeBaseWrapper, SynchronizationConfig, SystemSnapshot,
};
use statime_algo::LinkConfig;
#[cfg(feature = "pps")]
use statime_base::Duration;
use statime_base::{ActiveLinkData, ClockError, Link, LinkId, StdController};
use timestamped_socket::interface::InterfaceName;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, info};

pub const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

pub const MESSAGE_BUFFER_SIZE: usize = 32;

pub struct DaemonChannels {
    pub source_snapshots: Arc<std::sync::RwLock<HashMap<ClockId, ObservableSourceState>>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system_snapshot_receiver: tokio::sync::watch::Receiver<SystemSnapshot>,
}

/// Spawn the NTP daemon
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::too_many_arguments,
        reason = "FIXME: System needs a larger refactor to properly receive configuration"
    )
)]
pub async fn spawn<Controller: StdController<LinkConfig = LinkConfig> + Sync + Send + 'static>(
    create_controller: impl FnOnce(
        NtpClockWrapper,
    ) -> Result<(Controller, statime_base::ClockId), ClockError>,
    ntp_manager_config: SynchronizationConfig,
    source_defaults_config: SourceConfig,
    clock_config: ClockConfig,
    source_configs: &[NtpSourceConfig],
    server_configs: &[ServerConfig],
    #[cfg(target_os = "linux")] csptp_server_configs: &[crate::daemon::config::CsptpServerConfig],
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    #[cfg(target_os = "linux")] csptp_config: CsptpConfig,
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)>
where
    Controller::Link<Arc<Controller>>: Send,
{
    let ip_list = super::local_ip_provider::spawn()?;

    let (mut system, channels) = SystemTask::<Controller>::new(
        clock_config.clock,
        clock_config.interface,
        clock_config.timestamp_mode,
        create_controller,
        ntp_manager_config,
        &keyset,
        ip_list,
        !source_configs.is_empty(),
        #[cfg(target_os = "linux")]
        csptp_config,
    );

    for source_config in source_configs {
        match source_config {
            NtpSourceConfig::Standard(cfg) => {
                system.add_spawner(StandardSpawner::new(
                    cfg.first.clone(),
                    cfg.second.clone().with_defaults(source_defaults_config),
                ));
            }
            NtpSourceConfig::Nts(cfg) => {
                NtsSpawner::new(
                    cfg.first.clone(),
                    cfg.second.clone().with_defaults(source_defaults_config),
                )
                .map(|spawner| system.add_spawner(spawner))
                .map_err(|e| {
                    tracing::error!("Could not spawn source: {}", e);
                    std::io::Error::other(e)
                })?;
            }
            NtpSourceConfig::Pool(cfg) => {
                system.add_spawner(PoolSpawner::new(
                    cfg.first.clone(),
                    cfg.second.clone().with_defaults(source_defaults_config),
                ));
            }
            NtpSourceConfig::NtsPool(cfg) => {
                NtsPoolSpawner::new(
                    cfg.first.clone(),
                    cfg.second.clone().with_defaults(source_defaults_config),
                )
                .map(|spawner| system.add_spawner(spawner))
                .map_err(|e| {
                    tracing::error!("Could not spawn source: {}", e);
                    std::io::Error::other(e)
                })?;
            }
            NtpSourceConfig::Sock(cfg) => {
                system.add_spawner(SockSpawner::new(cfg.clone(), source_defaults_config));
            }
            #[cfg(feature = "pps")]
            NtpSourceConfig::Pps(cfg) => {
                system.add_spawner(PpsSpawner::new(cfg.clone(), source_defaults_config));
            }
            #[cfg(target_os = "linux")]
            NtpSourceConfig::Csptp(cfg) => {
                system.add_spawner(crate::daemon::spawn::csptp::CsptpSpawner::new(cfg.clone()));
            }
        }
    }

    for server_config in server_configs {
        system.add_server(server_config.to_owned());
    }

    #[cfg(target_os = "linux")]
    for csptp_server_config in csptp_server_configs {
        info!("Starting csptp server");
        system.add_csptp_server(csptp_server_config.to_owned());
    }

    let handle = tokio::spawn(async move { system.run().await });

    Ok((handle, channels))
}

struct SystemSpawnerData {
    id: SpawnerId,
    notify_tx: mpsc::Sender<SystemEvent>,
}

struct SystemTask<Controller: StdController> {
    controller: Arc<Controller>,
    ntp_manager: Arc<NtpManager>,

    #[cfg(target_os = "linux")]
    ptp_networking_ipv4: Option<statime_netptp::NetworkManager<Ipv4Addr>>,
    #[cfg(target_os = "linux")]
    ptp_networking_ipv6: Option<statime_netptp::NetworkManager<Ipv6Addr>>,
    // FIXME: Consider moving towards using AsRefs to pass the manager in statime_csptp.
    #[cfg(target_os = "linux")]
    csptp_manager:
        &'static statime_csptp::CsptpManager<std::sync::RwLock<statime_csptp::InternalState>>,

    system_snapshot_sender: tokio::sync::watch::Sender<SystemSnapshot>,
    source_snapshots: Arc<std::sync::RwLock<HashMap<ClockId, ObservableSourceState>>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,
    keyset: tokio::sync::watch::Receiver<Arc<KeySet>>,
    ip_list: tokio::sync::watch::Receiver<Arc<[IpAddr]>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    msg_for_system_tx: mpsc::Sender<MsgForSystem>,
    spawn_tx: mpsc::Sender<SpawnEvent>,
    spawn_rx: mpsc::Receiver<SpawnEvent>,

    sources: Arc<Mutex<HashMap<LinkId, SourceState>>>,
    servers: Vec<ServerData>,
    spawners: Vec<SystemSpawnerData>,

    clock: NtpClockWrapper,
    clock_id: statime_base::ClockId,

    // which timestamps to use (this is a hint, OS or hardware may ignore)
    timestamp_mode: TimestampMode,

    // bind the socket to a specific interface. This is relevant for hardware timestamping,
    // because the interface determines which clock is used to produce the timestamps.
    interface: Option<InterfaceName>,
}

impl<Controller: StdController<LinkConfig = LinkConfig> + Send + Sync> SystemTask<Controller>
where
    Controller::Link<Arc<Controller>>: Send + 'static,
{
    #[expect(clippy::too_many_arguments)]
    fn new(
        clock: NtpClockWrapper,
        interface: Option<InterfaceName>,
        timestamp_mode: TimestampMode,
        create_controller: impl FnOnce(
            NtpClockWrapper,
        )
            -> Result<(Controller, statime_base::ClockId), ClockError>,
        ntp_manager_config: SynchronizationConfig,
        keyset: &tokio::sync::watch::Receiver<Arc<KeySet>>,
        ip_list: tokio::sync::watch::Receiver<Arc<[IpAddr]>>,
        have_sources: bool,
        #[cfg(target_os = "linux")] csptp_config: CsptpConfig,
    ) -> (Self, DaemonChannels) {
        let Ok((controller, system_clock_id)) = create_controller(clock) else {
            tracing::error!("Could not create clock controller");
            std::process::exit(70);
        };
        let ntp_manager = NtpManager::new(ntp_manager_config, ip_list.borrow().clone());

        if have_sources && let Err(e) = clock.disable_ntp_algorithm() {
            tracing::error!("Could not control clock: {}", e);
            std::process::exit(70);
        }

        let system_snapshot = SystemSnapshot {
            time_snapshot: controller
                .clock_snapshot(system_clock_id)
                .expect("Unable to get system clock snapshot"),
            ntp_snapshot: ntp_manager.observe(),
        };

        // Create communication channels
        let (system_snapshot_sender, system_snapshot_receiver) =
            tokio::sync::watch::channel(system_snapshot);
        let source_snapshots = Arc::new(RwLock::new(HashMap::new()));
        let (server_data_sender, server_data_receiver) = tokio::sync::watch::channel(vec![]);
        let (msg_for_system_sender, msg_for_system_receiver) =
            tokio::sync::mpsc::channel(MESSAGE_BUFFER_SIZE);
        let (spawn_tx, spawn_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        // Build System and its channels
        (
            SystemTask {
                controller: Arc::new(controller),
                ntp_manager: Arc::new(ntp_manager),

                #[cfg(target_os = "linux")]
                ptp_networking_ipv4: None,
                #[cfg(target_os = "linux")]
                ptp_networking_ipv6: None,
                #[cfg(target_os = "linux")]
                // FIXME: For now, we leak the csptp_manager, as otherwise we would need to deal
                // with lifetimes on the individual sources, which is a pain. This is a one-time
                // operation, so its fine for now, but long term we should consider moving towards
                // an AsRef in statime_csptp for the references.
                csptp_manager: Box::leak(Box::new(statime_csptp::CsptpManager::new(
                    statime_csptp::CsptpConfig {
                        identity: csptp_config.identity,
                        priority_1: csptp_config.priority_1,
                        priority_2: csptp_config.priority_2,
                        clock_quality: csptp_config.clock_quality,
                        ptp_timescale: csptp_config.ptp_timescale,
                        time_traceable: csptp_config.time_traceable,
                        frequency_traceable: csptp_config.frequency_traceable,
                    },
                ))),

                system_snapshot_sender,
                source_snapshots: source_snapshots.clone(),
                server_data_sender,
                keyset: keyset.clone(),
                ip_list,

                msg_for_system_rx: msg_for_system_receiver,
                msg_for_system_tx: msg_for_system_sender,
                spawn_rx,
                spawn_tx,

                sources: Arc::default(),
                servers: vec![],
                spawners: vec![],
                clock,
                clock_id: system_clock_id,
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

    fn add_spawner(&mut self, spawner: impl Spawner + Send + Sync + 'static) -> SpawnerId {
        let (notify_tx, notify_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
        let id = spawner.get_id();
        let spawner_data = SystemSpawnerData { id, notify_tx };
        debug!(id=?spawner_data.id, ty=spawner.get_description(), addr=spawner.get_addr_description(), "Running spawner");
        self.spawners.push(spawner_data);
        let spawn_tx = self.spawn_tx.clone();
        // tokio::spawn(async move { spawner.run(spawn_tx, notify_rx).await });
        tokio::spawn(spawner_task(spawner, spawn_tx, notify_rx));
        id
    }

    async fn run(&mut self) -> std::io::Result<()> {
        let controller_run = Controller::run(self.controller.clone(), |duration| {
            tokio::time::sleep(duration)
        });

        let sender = self.system_snapshot_sender.clone();
        let controller = self.controller.clone();
        let ntp_manager = self.ntp_manager.clone();
        let sources = self.sources.clone();
        let clock_id = self.clock_id;
        let timer_loop = async move {
            loop {
                // Scope is needed to keep the future send.
                {
                    let time_snapshot = controller
                        .clock_snapshot(clock_id)
                        .expect("Unable to get system clock time snapshot");
                    let mut used_sources = controller.active_links();
                    used_sources.sort_by(|a, b| b.importance.total_cmp(&a.importance));
                    let sources = sources.lock().unwrap();
                    ntp_manager.update_time_snapshot(time_snapshot);

                    if let Some(used_sources) = used_sources
                        .into_iter()
                        .map(|ActiveLinkData { id, .. }| {
                            sources.get(&id).map(|state| (id, state.stype))
                        })
                        .collect::<Option<Vec<_>>>()
                    {
                        let ntp_snapshot =
                            ntp_manager.update_used_sources(used_sources.into_iter());
                        sender
                            .send(SystemSnapshot {
                                time_snapshot,
                                ntp_snapshot,
                            })
                            .ok();
                    } else {
                        sender.send_modify(|v| v.time_snapshot = time_snapshot);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        };

        let ntp_manager = self.ntp_manager.clone();
        let event_loop = async move {
            loop {
                tokio::select! {
                    opt_msg_for_system = self.msg_for_system_rx.recv() => {
                        match opt_msg_for_system {
                            None => {
                                // the channel closed and has no more messages in it
                                break
                            }
                            Some(msg_for_system) => {
                                self.handle_source_update(msg_for_system)
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
                        ntp_manager.update_ip_list(self.ip_list.borrow_and_update().clone());
                    }
                }
            }

            // the channel closed and has no more messages in it
            Ok(())
        };

        tokio::join!(event_loop, timer_loop, controller_run).0
    }

    async fn handle_source_update(&mut self, msg: MsgForSystem) -> std::io::Result<()> {
        tracing::debug!(?msg, "updating source");

        match msg {
            MsgForSystem::MustDemobilize(index) => {
                if let Err(e) = self.handle_source_demobilize(index).await {
                    unreachable!("Could not demobilize source: {}", e);
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

    async fn handle_source_network_issue(&mut self, index: LinkId) -> std::io::Result<()> {
        // Restart the source reusing its configuration.
        let state = self.sources.lock().unwrap().remove(&index).unwrap();
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

    async fn handle_source_unreachable(&mut self, index: LinkId) -> std::io::Result<()> {
        // Restart the source reusing its configuration.
        let state = self.sources.lock().unwrap().remove(&index).unwrap();
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

    async fn handle_source_demobilize(&mut self, index: LinkId) -> Result<(), ClockError> {
        // Restart the source reusing its configuration.
        let state = self.sources.lock().unwrap().remove(&index).unwrap();
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

    #[expect(
        clippy::too_many_lines,
        reason = "FIXME: Find a good way to split this function up."
    )]
    async fn create_source(
        &mut self,
        spawner_id: SpawnerId,
        mut params: SourceCreateParameters,
    ) -> Result<(), ClockError> {
        let source_id = params.get_id();
        info!(source_id=?source_id, addr=?params.get_addr(), spawner=?spawner_id, "new source");

        let source_controller = match params {
            SourceCreateParameters::Ntp(_) => Controller::create_tracked_link(
                self.controller.clone(),
                self.clock_id,
                None,
                Controller::LinkConfig::default(),
                Controller::TrackedLinkConfig::default(),
            ),
            #[cfg(target_os = "linux")]
            SourceCreateParameters::Csptp(_) => Controller::create_tracked_link(
                self.controller.clone(),
                self.clock_id,
                None,
                Controller::LinkConfig::default(),
                Controller::TrackedLinkConfig::default(),
            ),
            SourceCreateParameters::Sock(_) => Controller::create_untracked_link(
                self.controller.clone(),
                self.clock_id,
                None,
                Controller::LinkConfig::default(),
            ),
            #[cfg(feature = "pps")]
            SourceCreateParameters::Pps(ref params) => Controller::create_untracked_link(
                self.controller.clone(),
                self.clock_id,
                None,
                LinkConfig {
                    period: Some(Duration::from_f64_seconds(params.pps_config.period)),
                    ..Default::default()
                },
            ),
        }
        .expect("Unable to create controller for link");

        self.sources.lock().unwrap().insert(
            source_controller.id(),
            SourceState {
                source_id,
                spawner_id,
                stype: match &params {
                    SourceCreateParameters::Ntp(_) => SourceType::Ntp,
                    SourceCreateParameters::Sock(_) => SourceType::Sock,
                    #[cfg(feature = "pps")]
                    SourceCreateParameters::Pps(_) => SourceType::Pps,
                    #[cfg(target_os = "linux")]
                    SourceCreateParameters::Csptp(_) => SourceType::Csptp,
                },
            },
        );

        match params {
            SourceCreateParameters::Ntp(ref mut params) => {
                let link_id = source_controller.id();
                let source_controller =
                    StatimeBaseWrapper::new(source_controller, params.config.poll_interval_limits);

                let (source, initial_actions) = self.ntp_manager.new_source(
                    params.addr,
                    params.config,
                    params.protocol_version,
                    source_controller,
                    params.nts.take(),
                    source_id,
                    link_id,
                );

                SourceTask::spawn(
                    source_id,
                    link_id,
                    params.normalized_addr.to_string(),
                    params.addr,
                    self.interface,
                    self.clock,
                    self.timestamp_mode,
                    SourceChannels {
                        msg_for_system_sender: self.msg_for_system_tx.clone(),
                        source_snapshots: self.source_snapshots.clone(),
                    },
                    source,
                    initial_actions,
                );
            }
            SourceCreateParameters::Sock(ref params) => {
                SockSourceTask::spawn(
                    source_id,
                    self.clock,
                    SourceChannels {
                        msg_for_system_sender: self.msg_for_system_tx.clone(),
                        source_snapshots: self.source_snapshots.clone(),
                    },
                    source_controller,
                    params.sock_config.clone(),
                );
            }
            #[cfg(feature = "pps")]
            SourceCreateParameters::Pps(ref params) => {
                PpsSourceTask::spawn(
                    source_id,
                    SourceChannels {
                        msg_for_system_sender: self.msg_for_system_tx.clone(),
                        source_snapshots: self.source_snapshots.clone(),
                    },
                    source_controller,
                    params.pps_config.clone(),
                );
            }
            #[cfg(target_os = "linux")]
            SourceCreateParameters::Csptp(ref params) => match params.addr {
                IpAddr::V4(addr) => {
                    let network = if let Some(network) = &self.ptp_networking_ipv4 {
                        network.clone()
                    } else {
                        let manager = match statime_netptp::NetworkManager::new() {
                            Ok(manager) => manager,
                            Err(e) => {
                                tracing::warn!("Could not create source: {e}");
                                return Ok(());
                            }
                        };
                        self.ptp_networking_ipv4 = Some(manager.clone());
                        manager
                    };
                    let controller =
                        StatimeBaseWrapper::new(source_controller, PollIntervalLimits::default());
                    crate::daemon::csptp_source::CsptpSourceTask::spawn(
                        params.id,
                        addr,
                        params.config.clone(),
                        controller,
                        self.csptp_manager,
                        network,
                    );
                }
                IpAddr::V6(addr) => {
                    let network = if let Some(network) = self.ptp_networking_ipv6.as_ref() {
                        network.clone()
                    } else {
                        let manager = match statime_netptp::NetworkManager::new() {
                            Ok(manager) => manager,
                            Err(e) => {
                                tracing::warn!("Could not create source: {e}");
                                return Ok(());
                            }
                        };
                        self.ptp_networking_ipv6 = Some(manager.clone());
                        manager
                    };
                    let controller =
                        StatimeBaseWrapper::new(source_controller, PollIntervalLimits::default());
                    crate::daemon::csptp_source::CsptpSourceTask::spawn(
                        params.id,
                        addr,
                        params.config.clone(),
                        controller,
                        self.csptp_manager,
                        network,
                    );
                }
            },
        }

        // Try and find a related spawner and notify that spawner.
        // This makes sure that the spawner that initially sent the create event
        // is now aware that the source was added to the system.
        if let Some(s) = self.spawners.iter().find(|s| s.id == spawner_id) {
            let _ = s
                .notify_tx
                .send(SystemEvent::SourceRegistered(params))
                .await;
        }

        Ok(())
    }

    async fn handle_spawn_event(&mut self, event: SpawnEvent) -> Result<(), ClockError> {
        match event.action {
            SpawnAction::Create(params) => {
                self.create_source(event.id, params).await?;
            }
        }
        Ok(())
    }

    fn add_server(&mut self, config: ServerConfig) {
        let stats = ServerStats::default();
        self.servers.push(ServerData {
            stats: stats.clone(),
            config: config.clone(),
        });
        let server = self.ntp_manager.new_server(
            config.clone().into(),
            self.clock,
            self.keyset.borrow().clone(),
        );
        ServerTask::spawn(
            server,
            config,
            stats,
            self.keyset.clone(),
            NETWORK_WAIT_PERIOD,
        );
        let _ = self.server_data_sender.send(self.servers.clone());
    }

    #[cfg(target_os = "linux")]
    fn add_csptp_server(&mut self, config: crate::daemon::config::CsptpServerConfig) {
        let network_v4 = if let Some(network) = &self.ptp_networking_ipv4 {
            network.clone()
        } else {
            let manager = match statime_netptp::NetworkManager::new() {
                Ok(manager) => manager,
                Err(e) => {
                    tracing::warn!("Could not create csptp server: {e}");
                    return;
                }
            };
            self.ptp_networking_ipv4 = Some(manager.clone());
            manager
        };
        let network_v6 = if let Some(network) = &self.ptp_networking_ipv6 {
            network.clone()
        } else {
            let manager = match statime_netptp::NetworkManager::new() {
                Ok(manager) => manager,
                Err(e) => {
                    tracing::error!("Could not create csptp server: {e}");
                    return;
                }
            };
            self.ptp_networking_ipv6 = Some(manager.clone());
            manager
        };
        crate::daemon::csptp_server::CsptpServerTask::spawn(self.csptp_manager, network_v4, config);
        crate::daemon::csptp_server::CsptpServerTask::spawn(self.csptp_manager, network_v6, config);
    }
}

#[derive(Debug)]
struct SourceState {
    spawner_id: SpawnerId,
    source_id: ClockId,
    stype: SourceType,
}

#[derive(Debug, Clone)]
pub struct ServerData {
    pub stats: ServerStats,
    pub config: ServerConfig,
}
