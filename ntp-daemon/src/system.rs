use crate::{
    config::PeerConfig,
    peer::{MsgForSystem, PeerChannels, PeerIndex, PeerTask, ResetEpoch},
};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    ClockController, ClockUpdateResult, FilterAndCombine, FrequencyTolerance, NtpDuration,
    NtpInstant, PeerSnapshot, PollInterval, SystemConfig, SystemSnapshot,
};
use tracing::info;

use std::{error::Error, sync::Arc};
use tokio::sync::{mpsc, watch};

/// Spawn the NTP daemon
pub async fn spawn(
    config: &SystemConfig,
    peer_configs: &[PeerConfig],
) -> Result<(), Box<dyn Error>> {
    // shares the system state with all peers
    let global_system_snapshot = Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default()));

    // send the reset signal to all peers
    let reset_epoch: ResetEpoch = ResetEpoch::default();
    let (reset_tx, reset_rx) = watch::channel::<ResetEpoch>(reset_epoch);

    // receive peer snapshots from all peers
    let (msg_for_system_tx, msg_for_system_rx) = mpsc::channel::<MsgForSystem>(32);

    for (index, peer_config) in peer_configs.iter().enumerate() {
        let channels = PeerChannels {
            msg_for_system_sender: msg_for_system_tx.clone(),
            system_snapshots: global_system_snapshot.clone(),
            reset: reset_rx.clone(),
        };

        PeerTask::spawn(
            PeerIndex { index },
            &peer_config.addr,
            UnixNtpClock::new(),
            *config,
            channels,
        )
        .await?;
    }

    let mut peers = Peers::new(peer_configs.len());

    run(
        config,
        &mut peers,
        reset_epoch,
        global_system_snapshot,
        msg_for_system_rx,
        reset_tx,
    )
    .await
}

async fn run(
    config: &SystemConfig,
    peers: &mut Peers,
    mut reset_epoch: ResetEpoch,
    global_system_snapshot: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    mut msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    reset_tx: watch::Sender<ResetEpoch>,
) -> Result<(), Box<dyn Error>> {
    let mut controller = ClockController::new(UnixNtpClock::new());
    let mut snapshots = Vec::with_capacity(peers.len());

    while let Some(msg_for_system) = msg_for_system_rx.recv().await {
        let ntp_instant = NtpInstant::now();
        let system_poll = global_system_snapshot.read().await.poll_interval;

        if let NewMeasurement::No = peers.receive_update(
            msg_for_system,
            reset_epoch,
            ntp_instant,
            config.frequency_tolerance,
            config.distance_threshold,
            system_poll,
        ) {
            continue;
        }

        // remove snapshots from previous iteration
        snapshots.clear();

        // add all valid measurements to our list of snapshots
        snapshots.extend(peers.valid_snapshots());

        let result = FilterAndCombine::run(config, &snapshots, ntp_instant, system_poll);

        let clock_select = match result {
            Some(clock_select) => clock_select,
            None => {
                info!("filter and combine did not produce a result");
                continue;
            }
        };

        let offset_ms = clock_select.system_offset.to_seconds() * 1000.0;
        let jitter_ms = clock_select.system_jitter.to_seconds() * 1000.0;
        info!(offset_ms, jitter_ms, "system offset and jitter");

        let adjust_type = controller.update(
            config,
            clock_select.system_offset,
            clock_select.system_jitter,
            clock_select.system_root_delay,
            clock_select.system_root_dispersion,
            clock_select.system_peer_snapshot.leap_indicator,
            clock_select.system_peer_snapshot.time,
        );

        // Handle situations needing extra processing
        match adjust_type {
            ClockUpdateResult::Panic => {
                panic!(
                    r"Unusually large clock step suggested,
                            please manually verify system clock and reference clock
                                 state and restart if appropriate."
                )
            }
            ClockUpdateResult::Step => {
                peers.reset_all();

                reset_epoch = reset_epoch.inc();
                reset_tx.send_replace(reset_epoch);
            }
            _ => {}
        }

        // Handle updating system snapshot
        if let ClockUpdateResult::Ignore = adjust_type {
            // ignore this update
        } else {
            let mut global = global_system_snapshot.write().await;
            global.poll_interval = controller.preferred_poll_interval();
            global.leap_indicator = clock_select.system_peer_snapshot.leap_indicator;
        }
    }

    // the channel closed and has no more messages in it
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PeerStatus {
    /// This peer is demobilized, meaning we will not send further packets to it.
    /// Demobilized peers are kept because our logic is built around using indices,
    /// and removing a peer would mess up the indexing.
    Demobilized,
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

struct Peers {
    peers: Box<[PeerStatus]>,
}

enum NewMeasurement {
    Yes,
    No,
}

impl Peers {
    fn new(length: usize) -> Self {
        Self {
            peers: vec![PeerStatus::NoMeasurement; length].into(),
        }
    }

    fn len(&self) -> usize {
        self.peers.len()
    }

    fn valid_snapshots(&self) -> impl Iterator<Item = PeerSnapshot> + '_ {
        self.peers
            .iter()
            .filter_map(|peer_status| match peer_status {
                PeerStatus::Demobilized | PeerStatus::NoMeasurement => None,
                PeerStatus::Measurement(snapshot) => Some(*snapshot),
            })
    }

    fn receive_update(
        &mut self,
        msg: MsgForSystem,
        current_reset_epoch: ResetEpoch,

        local_clock_time: NtpInstant,
        frequency_tolerance: FrequencyTolerance,
        distance_threshold: NtpDuration,
        system_poll: PollInterval,
    ) -> NewMeasurement {
        match msg {
            MsgForSystem::MustDemobilize(index) => {
                self.peers[index.index] = PeerStatus::Demobilized;
            }
            MsgForSystem::NewMeasurement(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers[index.index] = PeerStatus::Measurement(snapshot);

                    let accept = snapshot.accept_synchronization(
                        local_clock_time,
                        frequency_tolerance,
                        distance_threshold,
                        system_poll,
                    );

                    if accept.is_ok() {
                        return NewMeasurement::Yes;
                    } else {
                        // the snapshot is updated (useful for observability)
                        // but we will not trigger a clock select based on this measurement
                    }
                }
            }
            MsgForSystem::UpdatedSnapshot(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers[index.index] = PeerStatus::Measurement(snapshot);
                }
            }
        }

        NewMeasurement::No
    }

    fn reset_all(&mut self) {
        for peer_status in self.peers.iter_mut() {
            use PeerStatus::*;

            *peer_status = match peer_status {
                Demobilized => Demobilized,
                Measurement(_) | NoMeasurement => NoMeasurement,
            };
        }
    }
}
