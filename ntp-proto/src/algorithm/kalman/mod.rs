use std::{collections::HashMap, fmt::Debug, hash::Hash};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    Measurement, NtpClock, NtpDuration, NtpLeapIndicator, NtpPacket, NtpTimestamp, PollInterval,
    SystemConfig, TimeSyncController,
};

use self::matrix::{Matrix, Vector};

mod matrix;

#[derive(Debug, Default, Copy, Clone)]
struct RttBuf {
    data: [f64; 8],
    next_idx: usize,
}

impl RttBuf {
    fn mean(&self) -> f64 {
        self.data.iter().sum::<f64>() / 8.
    }

    fn var(&self) -> f64 {
        let mean = self.mean();
        self.data
            .iter()
            .map(|v| (v - mean) * (v - mean))
            .sum::<f64>()
            / 7.
    }

    fn update(&mut self, rtt: f64) {
        self.data[self.next_idx] = rtt;
        self.next_idx = (self.next_idx + 1) % 8;
    }
}

#[derive(Debug, Clone)]
struct InitialPeerFilter {
    rtt_stats: RttBuf,
    init_offset: RttBuf,

    samples: i32,
}

impl InitialPeerFilter {
    fn update(&mut self, measurement: Measurement) {
        self.rtt_stats.update(measurement.delay.to_seconds());
        self.init_offset.update(measurement.offset.to_seconds());
        self.samples += 1;
    }
}

#[derive(Debug, Clone)]
struct PeerFilter {
    state: Vector,
    uncertainty: Matrix,
    clock_wander: f64,

    rtt_stats: RttBuf,

    precision_score: i32,
    poll_score: i32,
    desired_poll_interval: PollInterval,

    last_measurement: Measurement,
    last_packet: NtpPacket<'static>,
    prev_was_outlier: bool,

    last_iter: NtpTimestamp,
    filter_time: NtpTimestamp,
}

impl PeerFilter {
    // TODO: Make these configurable
    const PRECISION_LOW_P: f64 = 1. / 3.;
    const PRECISION_HIGH_P: f64 = 2. / 3.;
    const PRECISION_HISTERESIS: i32 = 16;
    const PRECISION_MIN_WEIGHT: f64 = 0.1;
    const POLL_LOW_WEIGHT: f64 = 0.4;
    const POLL_HIGH_WEIGHT: f64 = 0.4;
    const POLL_HISTERESIS: i32 = 16;

    fn progress_filtertime(&mut self, time: NtpTimestamp) {
        debug_assert!(time >= self.filter_time);
        if time < self.filter_time {
            return;
        }

        // Time step paremeters
        let delta_t = (time - self.filter_time).to_seconds();
        let update = Matrix::new(1.0, delta_t, 0.0, 1.0);
        let process_noise = Matrix::new(
            self.clock_wander * delta_t * delta_t * delta_t / 3.,
            self.clock_wander * delta_t * delta_t / 2.,
            self.clock_wander * delta_t * delta_t / 2.,
            self.clock_wander * delta_t,
        );

        // Kalman filter update
        self.state = update * self.state;
        self.uncertainty = update * self.uncertainty * update.transpose() + process_noise;
        self.filter_time = time;
    }

    fn absorb_measurement(&mut self, measurement: Measurement) -> (f64, f64) {
        // Measurement paramaters
        let delay_variance = self.rtt_stats.var();
        let m_delta_t = (measurement.offset - self.last_measurement.offset).to_seconds();

        // Kalman filter update
        let measurement_vec = Vector::new(
            measurement.offset.to_seconds(),
            (measurement.offset - self.last_measurement.offset).to_seconds(),
        );
        let measurement_transform = Matrix::new(1., 0., 0., m_delta_t);
        let measurement_noise = Matrix::new(
            delay_variance / 4.,
            delay_variance / 4.,
            delay_variance / 4.,
            delay_variance / 2.,
        );
        let difference = measurement_vec - measurement_transform * self.state;
        let difference_covariance =
            measurement_transform * self.uncertainty * measurement_transform.transpose()
                + measurement_noise;
        let update_strength =
            self.uncertainty * measurement_transform.transpose() * difference_covariance.inverse();
        self.state = self.state + update_strength * difference;
        self.uncertainty = ((Matrix::UNIT - update_strength * measurement_transform)
            * self.uncertainty)
            .symmetrize();

        // Statistics
        let chi = difference.inner(difference_covariance.inverse() * difference);
        let weight = measurement_noise.determinant() / difference_covariance.determinant();

        self.last_measurement = measurement;

        (chi, 1. - weight)
    }

    fn update_desired_poll(&mut self, weight: f64, chi: f64, config: &SystemConfig) {
        if weight < Self::POLL_LOW_WEIGHT {
            self.poll_score -= 1;
        } else if weight > Self::POLL_HIGH_WEIGHT {
            self.poll_score += 1;
        } else {
            self.poll_score -= self.poll_score.signum();
        }
        if chi >= 10.0_f64.ln() * 12.0 {
            self.desired_poll_interval = config.poll_limits.min;
            self.poll_score = 0;
        } else if self.poll_score <= -Self::POLL_HISTERESIS {
            self.desired_poll_interval = self.desired_poll_interval.inc(config.poll_limits);
            self.poll_score = 0;
        } else if self.poll_score >= Self::POLL_HISTERESIS {
            self.desired_poll_interval = self.desired_poll_interval.dec(config.poll_limits);
            self.poll_score = 0;
        }
    }

    fn update_wander_estimate(&mut self, chi: f64, weight: f64) {
        // Note that chi is exponentially distributed with mean 2
        // Also, we do not steer towards a smaller precision estimate when measurement noise dominates.
        if chi < -2. * (1. - Self::PRECISION_LOW_P).ln() && weight > Self::PRECISION_MIN_WEIGHT {
            self.precision_score -= 1;
        } else if chi > -2. * (1. - Self::PRECISION_HIGH_P).ln() {
            self.precision_score += 1;
        } else {
            self.precision_score -= self.precision_score.signum()
        }
        if self.precision_score <= -Self::PRECISION_HISTERESIS {
            self.clock_wander /= 4.0;
            self.precision_score = 0;
        } else if self.precision_score >= Self::PRECISION_HISTERESIS {
            self.clock_wander *= 4.0;
            self.precision_score = 0;
        }
    }

    fn update(
        &mut self,
        measurement: Measurement,
        packet: NtpPacket<'static>,
        config: &SystemConfig,
    ) -> bool {
        // Always keep the packet as last packet, since it reflects the most up-to-date
        // information on the synchronization quality of the remote and any upcoming leap seconds.
        self.last_packet = packet;

        if measurement.localtime < self.filter_time {
            // Ignore the past
            return false;
        }

        // Filter out one-time outliers (based on delay!)
        if !self.prev_was_outlier
            && (measurement.delay.to_seconds() - self.rtt_stats.mean())
                > 5. * self.rtt_stats.var().sqrt()
        {
            self.prev_was_outlier = true;
            self.last_iter = measurement.localtime;
            return false;
        }

        // Environment update
        self.progress_filtertime(measurement.localtime);
        self.rtt_stats.update(measurement.delay.to_seconds());

        let (chi, weight) = self.absorb_measurement(measurement);

        self.update_wander_estimate(chi, weight);
        self.update_desired_poll(weight, chi, config);

        info!(
            "peer offset {}+-{}, freq {}+-{}",
            self.state.entry(0) * 1000.,
            (self.uncertainty.entry(0, 0)
                + self.last_packet.root_dispersion().to_seconds()
                    * self.last_packet.root_dispersion().to_seconds())
            .sqrt()
                * 1000.,
            self.state.entry(1) * 1000.,
            self.uncertainty.entry(1, 1).sqrt() * 1000.
        );

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerTimeSnapshot {
    Full {
        offset: NtpDuration,
        offset_uncertainty: NtpDuration,

        freq: f64,
        freq_uncertainty: f64,

        stratum: u8,

        leap_indicator: NtpLeapIndicator,
        root_delay: NtpDuration,
        root_dispersion: NtpDuration,
    },
    Initial {
        samples: i32,
    },
}

#[derive(Debug, Clone)]
enum PeerState {
    Initial(InitialPeerFilter),
    Stable(PeerFilter),
}

impl PeerState {
    // TODO: Make these configurable
    const INITIAL_WANDER: f64 = 1e-14;
    const INITIAL_FREQ_UNCERTAINTY: f64 = 100e-6 * 100e-6;

    fn new() -> Self {
        PeerState::Initial(InitialPeerFilter {
            rtt_stats: RttBuf::default(),
            init_offset: RttBuf::default(),
            samples: 0,
        })
    }

    fn update(
        &mut self,
        measurement: Measurement,
        packet: NtpPacket<'static>,
        config: &SystemConfig,
    ) -> bool {
        match self {
            PeerState::Initial(filter) => {
                filter.update(measurement);
                if filter.samples == 8 {
                    *self = PeerState::Stable(PeerFilter {
                        state: Vector::new(filter.init_offset.mean(), 0.),
                        uncertainty: Matrix::new(
                            filter.init_offset.var(),
                            0.,
                            0.,
                            Self::INITIAL_FREQ_UNCERTAINTY,
                        ),
                        clock_wander: Self::INITIAL_WANDER,
                        rtt_stats: filter.rtt_stats,
                        precision_score: 0,
                        poll_score: 0,
                        desired_poll_interval: config.initial_poll,
                        last_measurement: measurement,
                        last_packet: packet,
                        prev_was_outlier: false,
                        last_iter: measurement.localtime,
                        filter_time: measurement.localtime,
                    });
                    true
                } else {
                    false
                }
            }
            PeerState::Stable(filter) => filter.update(measurement, packet, config),
        }
    }

    fn snapshot(&self) -> PeerTimeSnapshot {
        match self {
            PeerState::Initial(filter) => PeerTimeSnapshot::Initial {
                samples: filter.samples,
            },
            PeerState::Stable(filter) => PeerTimeSnapshot::Full {
                offset: NtpDuration::from_seconds(filter.state.entry(0)),
                offset_uncertainty: NtpDuration::from_seconds(
                    filter.uncertainty.entry(0, 0).sqrt(),
                ),
                freq: filter.state.entry(1),
                freq_uncertainty: filter.uncertainty.entry(1, 1).sqrt(),
                stratum: filter.last_packet.stratum(),
                leap_indicator: filter.last_packet.leap(),
                root_delay: filter.last_packet.root_delay(),
                root_dispersion: filter.last_packet.root_dispersion(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct KalmanClockController<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> {
    peers: HashMap<PeerID, (PeerState, bool)>,
    clock: C,
    config: SystemConfig,
}

impl<C: NtpClock, PeerID: Hash + Eq + Copy + Debug> TimeSyncController<C, PeerID>
    for KalmanClockController<C, PeerID>
{
    type PeerTimeSnapshot = PeerTimeSnapshot;

    fn new(clock: C, config: SystemConfig) -> Self {
        KalmanClockController {
            peers: HashMap::new(),
            clock,
            config,
        }
    }

    fn update_config(&mut self, config: SystemConfig) {
        self.config = config;
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
        if self
            .peers
            .get_mut(&id)
            .map(|state| state.0.update(measurement, packet, &self.config) & state.1)
            == Some(true)
        {
            //todo!()
            None
        } else {
            None
        }
    }

    fn peer_snapshot(&self, id: PeerID) -> Option<Self::PeerTimeSnapshot> {
        self.peers.get(&id).map(|v| v.0.snapshot())
    }
}
