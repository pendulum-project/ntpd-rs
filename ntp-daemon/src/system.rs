use crate::{
    config::{PeerConfig, PoolPeerConfig, ServerConfig, StandardPeerConfig},
    peer::{MsgForSystem, PeerChannels},
    peer_manager::{Peers, SpawnTask},
};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{NtpClock, SystemConfig, SystemSnapshot};

use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};

pub struct DaemonChannels<C: NtpClock> {
    pub config: Arc<tokio::sync::RwLock<SystemConfig>>,
    pub peers: Arc<tokio::sync::RwLock<Peers<C>>>,
    pub system: Arc<tokio::sync::RwLock<SystemSnapshot>>,
}

/// Spawn the NTP daemon
pub async fn spawn(
    config: SystemConfig,
    peer_configs: &[PeerConfig],
    server_configs: &[ServerConfig],
) -> std::io::Result<(
    JoinHandle<std::io::Result<()>>,
    DaemonChannels<UnixNtpClock>,
)> {
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
    let sysconfig = config;
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let mut peers = Peers::new(
        PeerChannels {
            msg_for_system_sender: msg_for_system_tx.clone(),
            system_snapshots: system.clone(),
            system_config: config.clone(),
        },
        UnixNtpClock::new(),
        spawn_task_tx,
        sysconfig,
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

    let peers = Arc::new(tokio::sync::RwLock::new(peers));

    let channels = DaemonChannels {
        config: config.clone(),
        peers: peers.clone(),
        system: system.clone(),
    };

    let handle = tokio::spawn(async move {
        let mut system = System {
            config,
            global_system_snapshot: system,
            peers_rwlock: peers,

            msg_for_system_rx,
            spawn_task_rx,
        };

        system.run().await
    });

    Ok((handle, channels))
}

struct System<C: NtpClock> {
    config: Arc<tokio::sync::RwLock<SystemConfig>>,
    global_system_snapshot: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    peers_rwlock: Arc<tokio::sync::RwLock<Peers<C>>>,

    msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    spawn_task_rx: mpsc::Receiver<SpawnTask>,
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
                            // ensure the config is not updated in the middle of clock selection
                            let config = *self.config.read().await;

                            let result = self.peers_rwlock
                                .write()
                                .await
                                .update(msg_for_system, config)
                                .await;

                            if let Some((used_peers, timedata)) = result {
                                let system_peer_snapshot = self
                                    .peers_rwlock
                                    .read()
                                    .await
                                    .peer_snapshot(used_peers[0])
                                    .unwrap();
                                let mut global = self.global_system_snapshot.write().await;
                                global.time_snapshot = timedata;
                                global.stratum = system_peer_snapshot
                                    .stratum
                                    .saturating_add(1);
                                global.reference_id = system_peer_snapshot.reference_id;
                                global.accumulated_steps_threshold = config.accumulated_threshold;
                            }
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
                            self.peers_rwlock
                                .write()
                                .await
                                .spawn_task(spawn_task.peer_address, spawn_task.address);
                        }
                    }
                }
            }
        }

        // the channel closed and has no more messages in it
        Ok(())
    }
}
