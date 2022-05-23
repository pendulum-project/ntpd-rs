mod peer;

use peer::{start_peer, MsgForSystem, ResetEpoch};
use ntp_os_clock::UnixNtpClock;
use ntp_proto::{
    ClockController, ClockUpdateResult, FilterAndCombine, NtpInstant, PeerSnapshot, SystemConfig,
    SystemSnapshot,
};
use tracing::info;

use std::{error::Error, sync::Arc};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, Copy)]
enum PeerState {
    Demobilized,
    AwaitingReset,
    Valid(PeerSnapshot),
}

impl PeerState {
    const fn get_snapshot(&self) -> Option<PeerSnapshot> {
        match self {
            PeerState::Demobilized | PeerState::AwaitingReset => None,
            PeerState::Valid(snapshot) => Some(*snapshot),
        }
    }

    fn reset(&mut self) {
        *self = match self {
            PeerState::Demobilized => PeerState::Demobilized,
            PeerState::AwaitingReset => PeerState::AwaitingReset,
            PeerState::Valid(_) => PeerState::AwaitingReset,
        };
    }
}

pub async fn start_system(
    config: &SystemConfig,
    peer_addresses: &[&str],
) -> Result<(), Box<dyn Error>> {
    // shares the system state with all peers
    let global_system_snapshot = Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default()));

    // send the reset signal to all peers
    let reset_epoch: ResetEpoch = ResetEpoch::default();
    let (reset_tx, reset_rx) = watch::channel::<ResetEpoch>(reset_epoch);

    // receive peer snapshots from all peers
    let (msg_for_system_tx, msg_for_system_rx) = mpsc::channel::<MsgForSystem>(32);

    for (index, address) in peer_addresses.iter().enumerate() {
        start_peer(
            index,
            address,
            UnixNtpClock::new(),
            *config,
            msg_for_system_tx.clone(),
            global_system_snapshot.clone(),
            reset_rx.clone(),
        )
        .await
        .unwrap();
    }

    let mut peers = vec![PeerState::AwaitingReset; peer_addresses.len()];

    run_system(
        config,
        &mut peers,
        reset_epoch,
        global_system_snapshot,
        msg_for_system_rx,
        reset_tx,
    )
    .await
}

async fn run_system(
    config: &SystemConfig,
    peers: &mut [PeerState],
    mut reset_epoch: ResetEpoch,
    global_system_snapshot: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    mut msg_for_system_rx: mpsc::Receiver<MsgForSystem>,
    reset_tx: watch::Sender<ResetEpoch>,
) -> Result<(), Box<dyn Error>> {
    let mut controller = ClockController::new(UnixNtpClock::new());
    let mut snapshots = Vec::with_capacity(peers.len());

    while let Some(msg_for_system) = msg_for_system_rx.recv().await {
        receive_msg_for_system(peers, msg_for_system, reset_epoch);

        // remove snapshots from previous iteration
        snapshots.clear();

        // add all valid measurements to our list of snapshots
        snapshots.extend(peers.iter().filter_map(PeerState::get_snapshot));

        let ntp_instant = NtpInstant::now();
        let system_poll = global_system_snapshot.read().await.poll_interval;
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
            clock_select.system_offset,
            clock_select.system_jitter,
            clock_select.system_peer_snapshot.root_delay,
            clock_select.system_peer_snapshot.root_dispersion,
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
                for peer_state in peers.iter_mut() {
                    peer_state.reset();
                }

                reset_epoch = reset_epoch.inc();
                reset_tx.send_replace(reset_epoch);
            }
            _ => {}
        }

        // Handle updating system snapshot
        match adjust_type {
            ClockUpdateResult::Ignore => {}
            _ => {
                let mut global = global_system_snapshot.write().await;
                global.poll_interval = controller.preferred_poll_interval();
                global.leap_indicator = clock_select.system_peer_snapshot.leap_indicator;
            }
        }
    }

    // the channel closed and has no more messages in it
    Ok(())
}

fn receive_msg_for_system(
    peers: &mut [PeerState],
    msg_for_system: MsgForSystem,
    current_reset_epoch: ResetEpoch,
) {
    match msg_for_system {
        MsgForSystem::MustDemobilize(index) => {
            peers[index] = PeerState::Demobilized;
        }
        MsgForSystem::Snapshot(index, msg_reset_epoch, snapshot) => {
            if current_reset_epoch == msg_reset_epoch {
                peers[index] = PeerState::Valid(snapshot);
            }
        }
    }
}
