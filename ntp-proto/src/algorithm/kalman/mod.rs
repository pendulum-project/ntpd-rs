use std::{collections::HashMap, fmt::Debug, hash::Hash};

use tracing::{instrument, info};

use crate::{
    Measurement, NtpClock, NtpDuration, NtpPacket, NtpTimestamp, ObservablePeerTimedata,
    SystemConfig, TimeSyncController,
};

use self::{config::AlgorithmConfig, peer::PeerState};

mod config;
mod matrix;
mod peer;
mod select;

#[derive(Debug, Clone)]
pub struct KalmanClockController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> {
    peers: HashMap<PeerID, (PeerState, bool)>,
    clock: C,
    config: SystemConfig,
    algo_config: AlgorithmConfig,
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> KalmanClockController<C, PeerID> {
    #[instrument(skip(self))]
    fn update_peer(
        &mut self,
        id: PeerID,
        measurement: Measurement,
        packet: NtpPacket<'static>,
    ) -> bool {
        self.peers.get_mut(&id).map(|state| {
            state
                .0
                .update(&self.config, &self.algo_config, measurement, packet)
                & state.1
        }) == Some(true)
    }

    fn update_clock(&mut self, time: NtpTimestamp) -> Option<(Vec<PeerID>, crate::TimeSnapshot)> {
        // ensure all filters represent the same (current) time
        if self
            .peers
            .iter()
            .filter_map(|(_, (state, _))| state.get_filtertime())
            .any(|peertime| time - peertime < NtpDuration::ZERO)
        {
            return None;
        }
        for (_, (state, _)) in self.peers.iter_mut() {
            state.progress_filtertime(time);
        }

        // Select peers that agree on the current time
        if let Some(selection) = select::select(
            &self.config,
            &self.algo_config,
            self.peers
                .iter()
                .filter_map(|(index, (state, usable))| {
                    if *usable {
                        state.get_select_range().map(|v| (*index, v))
                    } else {
                        None
                    }
                })
                .collect(),
        ) {
            let (mut estimate, mut uncertainty) = self
                .peers
                .get(
                    selection
                        .first()
                        .expect("Selection should not return empty vector"),
                )
                .unwrap()
                .0
                .get_timeestimate()
                .expect("Could not get time estimate for selected peer");
            let mut used_peers = vec![(*selection.first().expect("Selection should not return empty vector"), uncertainty.determinant())];

            for index in selection.iter().skip(1) {
                let (peer_estimate, peer_uncertainty) = self.peers.get(index).unwrap().0.get_timeestimate().expect("Could not get time estimate for selected peer");

                used_peers.push((*index, peer_uncertainty.determinant()));

                // Merge measurements
                let mixer = (uncertainty + peer_uncertainty).inverse();
                estimate = estimate + uncertainty * mixer * (peer_estimate - estimate);
                uncertainty = uncertainty * mixer * peer_uncertainty;
            }

            used_peers.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            None   
        } else {
            info!("No concensus cluster found");
            None
        }
    }
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> TimeSyncController<C, PeerID>
    for KalmanClockController<C, PeerID>
{
    type AlgorithmConfig = AlgorithmConfig;

    fn new(clock: C, config: SystemConfig, algo_config: Self::AlgorithmConfig) -> Self {
        // Setup clock
        clock
            .bare_update(
                NtpDuration::ZERO,
                NtpDuration::ZERO,
                NtpDuration::ZERO,
                crate::NtpLeapIndicator::Unknown,
            )
            .expect("Unable to change system time");
        clock
            .set_freq(0.0)
            .expect("Unable to set system clock frequency");

        KalmanClockController {
            peers: HashMap::new(),
            clock,
            config,
            algo_config,
        }
    }

    fn update_config(&mut self, config: SystemConfig, algo_config: Self::AlgorithmConfig) {
        self.config = config;
        self.algo_config = algo_config;
    }

    fn peer_add(&mut self, id: PeerID) {
        self.peers.insert(id, (PeerState::new(), false));
    }

    fn peer_remove(&mut self, id: PeerID) {
        self.peers.remove(&id);
    }

    fn peer_update(&mut self, id: PeerID, usable: bool) {
        if let Some(state) = self.peers.get_mut(&id) {
            state.1 = usable;
        }
    }

    fn peer_measurement(
        &mut self,
        id: PeerID,
        measurement: Measurement,
        packet: NtpPacket<'static>,
    ) -> Option<(Vec<PeerID>, crate::TimeSnapshot)> {
        if self.update_peer(id, measurement, packet) {
            self.update_clock(measurement.localtime)
        } else {
            None
        }
    }

    fn peer_snapshot(&self, id: PeerID) -> Option<ObservablePeerTimedata> {
        self.peers.get(&id).and_then(|v| v.0.snapshot())
    }
}
