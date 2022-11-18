use crate::{
    config::{PeerConfig, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    peer::{MsgForSystem, PeerChannels},
    peer_manager::{Peers, ServerData, SpawnTask},
    ObservablePeerState,
};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{NtpClock, SystemConfig, SystemSnapshot};

use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};

pub struct DaemonChannels {
    pub config_receiver: tokio::sync::watch::Receiver<SystemConfig>,
    pub config_sender: tokio::sync::watch::Sender<SystemConfig>,
    pub peer_snapshots_receiver: tokio::sync::watch::Receiver<Vec<ObservablePeerState>>,
    pub server_data_receiver: tokio::sync::watch::Receiver<Vec<ServerData>>,
    pub system: Arc<tokio::sync::RwLock<SystemSnapshot>>,
}

/// Spawn the NTP daemon
pub async fn spawn(
    config: SystemConfig,
    peer_configs: &[PeerConfig],
    server_configs: &[ServerConfig],
) -> std::io::Result<(JoinHandle<std::io::Result<()>>, DaemonChannels)> {
    // receive peer snapshots from all peers
    let (msg_for_system_tx, msg_for_system_rx) = mpsc::channel::<MsgForSystem>(32);

    let (spawn_task_tx, spawn_task_rx) = mpsc::channel::<SpawnTask>(32);

    // System snapshot
    let system_snapshot = SystemSnapshot {
        stratum: config.local_stratum,
        ..Default::default()
    };

    // Daemon channels
    let system = Arc::new(tokio::sync::RwLock::new(system_snapshot));
    let (config_sender, config_receiver) = tokio::sync::watch::channel(config);
    let mut peers = Peers::new(
        PeerChannels {
            msg_for_system_sender: msg_for_system_tx.clone(),
            system_snapshots: system.clone(),
            system_config_receiver: config_receiver.clone(),
        },
        UnixNtpClock::new(),
        spawn_task_tx,
        config,
    );

    for peer_config in peer_configs {
        match peer_config {
            PeerConfig::Standard(StandardPeerConfig { addr }) => {
                peers.add_peer(addr.clone()).await;
            }
            PeerConfig::Pool(PoolPeerConfig {
                addr, max_peers, ..
            }) => {
                peers.add_new_pool(addr.clone(), *max_peers).await;
            }
        }
    }

    for server_config in server_configs.iter() {
        peers.add_server(server_config.to_owned()).await;
    }

    let (peer_snapshots_sender, peer_snapshots_receiver) =
        tokio::sync::watch::channel(peers.observe_peers().collect());

    let (server_data_sender, server_data_receiver) =
        tokio::sync::watch::channel(peers.servers().collect());

    let channels = DaemonChannels {
        config_sender,
        config_receiver: config_receiver.clone(),
        peer_snapshots_receiver,
        server_data_receiver,
        system: system.clone(),
    };

    let handle = tokio::spawn(async move {
        let mut system = System {
            config_receiver,
            config,
            global_system_snapshot: system,
            peer_snapshots_sender,
            server_data_sender,

            msg_for_system_rx,
            spawn_task_rx,

            peers,
        };

        system.run().await
    });

    Ok((handle, channels))
}

struct System<C: NtpClock> {
    config_receiver: tokio::sync::watch::Receiver<SystemConfig>,
    config: SystemConfig,
    global_system_snapshot: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    peer_snapshots_sender: tokio::sync::watch::Sender<Vec<ObservablePeerState>>,
    server_data_sender: tokio::sync::watch::Sender<Vec<ServerData>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    spawn_task_rx: mpsc::Receiver<SpawnTask>,

    peers: Peers<C>,
}

impl<C: NtpClock> System<C> {
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
                            let result = self.peers
                                .update(msg_for_system)
                                .await;

                            if let Some((used_peers, timedata)) = result {
                                let system_peer_snapshot = self.peers
                                    .peer_snapshot(used_peers[0])
                                    .unwrap();
                                let mut global = self.global_system_snapshot.write().await;
                                global.time_snapshot = timedata;
                                global.stratum = system_peer_snapshot
                                    .stratum
                                    .saturating_add(1);
                                global.reference_id = system_peer_snapshot.reference_id;
                                global.accumulated_steps_threshold = self.config.accumulated_threshold;
                            }

                            // Don't care if there is no receiver for peer snapshots (which might happen if
                            // we don't enable observing in the configuration)
                            let _ = self.peer_snapshots_sender.send(self.peers.observe_peers().collect());
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
                            self.peers
                                .spawn_task(spawn_task.peer_address, spawn_task.address);

                            // Don't care if there is no receiver for peer snapshots (which might happen if
                            // we don't enable observing in the configuration)
                            let _ = self.peer_snapshots_sender.send(self.peers.observe_peers().collect());
                            let _ = self.server_data_sender.send(self.peers.servers().collect());
                        }
                    }
                }
                _ = self.config_receiver.changed(), if self.config_receiver.has_changed().is_ok() => {
                    let config = *self.config_receiver.borrow_and_update();
                    self.peers.update_config(config);
                    self.config = config;
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }
}
