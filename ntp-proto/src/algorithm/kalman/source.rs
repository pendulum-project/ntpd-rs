use std::default;

/// This module implements a kalman filter to filter the measurements
/// provided by the sources.
///
/// The filter tracks the time difference between the local and remote
/// timescales. For ease of implementation, it actually is programmed
/// mostly as if the local timescale is absolute truth, and the remote
/// timescale is the one that is estimated. The filter state is kept at
/// a local timestamp t, and progressed in time as needed for processing
/// measurements and producing estimation outputs.
///
/// This approach is chosen so that it is possible to line up the filters
/// from multiple sources (this has no real meaning when using remote
/// timescales for that), and makes sure that we control the timescale
/// used to express the filter in.
///
/// The state is a vector (D, w) where
///  - D is the offset between the remote and local timescales
///  - w is (in seconds per second) the frequency difference.
///
/// For process noise, we assume this is fully resultant from frequency
/// drift between the local and remote timescale, and that this frequency
/// drift is assumed to be the result from a (limit of) a random walk
/// process (wiener process). Under this assumption, a timechange from t1
/// to t2 has a state propagation matrix
/// 1 (t2-t1)
/// 0    0
/// and a noise matrix given by
/// v*(t2-t1)^3/3 v*(t2-t1)^2/2
/// v*(t2-t1)^2/2   v*(t2-t1)
/// where v is a constant describing how much the frequency drifts per
/// unit of time.
///
/// This modules input consists of measurements containing:
///  - the time of the measurement t_m
///  - the measured offset d
///  - the measured transmission delay r
///
/// On these, we assume that
///  - there is no impact from frequency differences on r
///  - individual measurements are independent
///
/// This information on its own is not enough to feed the kalman filter.
/// For this, a further piece of information is needed: a measurement
/// related to the frequency difference. Although mathematically not
/// entirely sound, we construct the frequency measurement also using
/// the previous measurement (which we will denote with t_p and D_p).
/// It turns out this works well in practice
///
/// The observation is then the vector (D, D-D_p), and the observation
/// matrix is given by
/// 1   0
/// 0 t_m-t_p
///
/// To estimate the measurement noise, the variance s of the transmission
/// delays r is used. Writing r as r1 - r2, where r1 is the time
/// difference on the client-to-server leg and r2 the time difference on
/// the server to client leg, we have Var(D) = Var(1/2 (r1 + r2)) = 1/4
/// Var(r1 - r2) = 1/4 Var(r). Furthermore Var(D+Dp) = Var(D) + Var(Dp)
/// = 1/2 Var(r) and Covar(D, D+Dp) = Covar(D, D) + Covar(D, Dp) = Var(D)
/// s/4 s/4
/// s/4 s/2
///
/// This setup leaves two major issues:
///  - How often do we want measurements (what is the desired polling interval)
///  - What is v
///
/// The polling interval is changed dynamically such that
/// approximately each measurement is about halved before contributing to
/// the state (see below).
///
/// The value for v is determined by observing how well the distribution
/// of measurement errors matches up with what we would statistically expect.
/// If they are often too small, v is quartered, and if they are often too
/// large, v is quadrupled (note, this corresponds with doubling/halving
/// the more intuitive standard deviation).
use tracing::{debug, trace};

use crate::{
    algorithm::{KalmanControllerMessage, KalmanSourceMessage, SourceController},
    config::SourceDefaultsConfig,
    source::Measurement,
    time_types::{NtpDuration, NtpTimestamp, PollInterval, PollIntervalLimits},
    ObservableSourceTimedata,
};

use super::{
    config::AlgorithmConfig,
    matrix::{Matrix, Vector},
    sqr, SourceSnapshot,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct KalmanState {
    pub state: Vector<2>,
    pub uncertainty: Matrix<2, 2>,
    // current time of the filter state
    pub time: NtpTimestamp,
}

pub(super) struct MeasurementStats {
    // Probability that the measurement was as close or closer to the prediction from the filter
    pub observe_probability: f64,
    // How much the measurement affected the filter state
    pub weight: f64,
}

impl KalmanState {
    #[must_use]
    pub fn progress_time(&self, time: NtpTimestamp, wander: f64) -> KalmanState {
        debug_assert!(!time.is_before(self.time));
        if time.is_before(self.time) {
            return *self;
        }

        // Time step parameters
        let delta_t = (time - self.time).to_seconds();
        let update = Matrix::new([[1.0, delta_t], [0.0, 1.0]]);
        let process_noise = Matrix::new([
            [
                wander * delta_t * delta_t * delta_t / 3.,
                wander * delta_t * delta_t / 2.,
            ],
            [wander * delta_t * delta_t / 2., wander * delta_t],
        ]);

        // Kalman filter update
        KalmanState {
            state: update * self.state,
            uncertainty: update * self.uncertainty * update.transpose() + process_noise,
            time,
        }
    }

    #[must_use]
    pub fn absorb_measurement(
        &self,
        measurement: Matrix<1, 2>,
        value: Vector<1>,
        noise: Matrix<1, 1>,
    ) -> (KalmanState, MeasurementStats) {
        let difference = value - measurement * self.state;
        let difference_covariance =
            measurement * self.uncertainty * measurement.transpose() + noise;
        let update_strength =
            self.uncertainty * measurement.transpose() * difference_covariance.inverse();

        // Statistics
        let observe_probability =
            chi_1(difference.inner(difference_covariance.inverse() * difference));
        // Calculate an indicator of how much of the measurement was incorporated
        // into the state. 1.0 - is needed here as this should become lower as
        // measurement noise's contribution to difference uncertainty increases.
        let weight = 1.0 - noise.determinant() / difference_covariance.determinant();

        (
            KalmanState {
                state: self.state + update_strength * difference,
                uncertainty: ((Matrix::unit() - update_strength * measurement) * self.uncertainty)
                    .symmetrize(),
                time: self.time,
            },
            MeasurementStats {
                observe_probability,
                weight,
            },
        )
    }

    #[must_use]
    pub fn merge(&self, other: &KalmanState) -> KalmanState {
        debug_assert_eq!(self.time, other.time);

        let mixer = (self.uncertainty + other.uncertainty).inverse();

        KalmanState {
            state: self.state + self.uncertainty * mixer * (other.state - self.state),
            uncertainty: self.uncertainty * mixer * other.uncertainty,
            time: self.time,
        }
    }

    #[must_use]
    pub fn add_server_dispersion(&self, dispersion: f64) -> KalmanState {
        KalmanState {
            state: self.state,
            uncertainty: self.uncertainty + Matrix::new([[sqr(dispersion), 0.0], [0.0, 0.0]]),
            time: self.time,
        }
    }

    #[must_use]
    pub fn offset(&self) -> f64 {
        self.state.ventry(0)
    }

    #[must_use]
    pub fn offset_variance(&self) -> f64 {
        self.uncertainty.entry(0, 0)
    }

    #[must_use]
    pub fn frequency(&self) -> f64 {
        self.state.ventry(1)
    }

    #[must_use]
    pub fn frequency_variance(&self) -> f64 {
        self.uncertainty.entry(1, 1)
    }

    #[must_use]
    pub fn process_offset_steering(&self, steer: f64) -> KalmanState {
        KalmanState {
            state: self.state - Vector::new_vector([steer, 0.0]),
            uncertainty: self.uncertainty,
            time: self.time + NtpDuration::from_seconds(steer),
        }
    }

    #[must_use]
    pub fn process_frequency_steering(
        &self,
        time: NtpTimestamp,
        steer: f64,
        wander: f64,
    ) -> KalmanState {
        let mut result = self.progress_time(time, wander);
        result.state = result.state - Vector::new_vector([0.0, steer]);
        result
    }
}

#[derive(Debug, Default, Copy, Clone)]
struct AveragingBuffer {
    data: [f64; 8],
    next_idx: usize,
}

// Large frequency uncertainty as early time essentially gives no reasonable info on frequency.
const INITIALIZATION_FREQ_UNCERTAINTY: f64 = 100.0;

/// Approximation of 1 - the chi-squared cdf with 1 degree of freedom
/// source: https://en.wikipedia.org/wiki/Error_function
fn chi_1(chi: f64) -> f64 {
    const P: f64 = 0.3275911;
    const A1: f64 = 0.254829592;
    const A2: f64 = -0.284496736;
    const A3: f64 = 1.421413741;
    const A4: f64 = -1.453152027;
    const A5: f64 = 1.061405429;

    let x = (chi / 2.).sqrt();
    let t = 1. / (1. + P * x);
    (A1 * t + A2 * t * t + A3 * t * t * t + A4 * t * t * t * t + A5 * t * t * t * t * t)
        * (-(x * x)).exp()
}

impl AveragingBuffer {
    fn mean(&self) -> f64 {
        self.data.iter().sum::<f64>() / (self.data.len() as f64)
    }

    fn variance(&self) -> f64 {
        let mean = self.mean();
        self.data.iter().map(|v| sqr(v - mean)).sum::<f64>() / ((self.data.len() - 1) as f64)
    }

    fn update(&mut self, rtt: f64) {
        self.data[self.next_idx] = rtt;
        self.next_idx = (self.next_idx + 1) % self.data.len();
    }
}

#[derive(Debug, Clone)]
struct InitialSourceFilter {
    noise_estimator: MeasurementNoiseEstimator,
    init_offset: AveragingBuffer,
    last_measurement: Option<Measurement>,

    samples: i32,
}

impl InitialSourceFilter {
    fn update(&mut self, measurement: Measurement) {
        if let MeasurementNoiseEstimator::RoundtripDelay(mut roundtriptime_stats) =
            self.noise_estimator
        {
            if let Some(delay) = measurement.delay {
                roundtriptime_stats.update(delay.to_seconds());
            }
        }
        self.init_offset.update(measurement.offset.to_seconds());
        self.samples += 1;
        self.last_measurement = Some(measurement);
        debug!(samples = self.samples, "Initial source update");
    }

    fn process_offset_steering(&mut self, steer: f64) {
        for sample in self.init_offset.data.iter_mut() {
            *sample -= steer;
        }
    }
}

#[derive(Debug, Clone)]
pub enum MeasurementNoiseEstimator {
    RoundtripDelay(AveragingBuffer),
    Constant(f64),
}

#[derive(Debug, Clone)]
struct SourceFilter {
    state: KalmanState,
    clock_wander: f64,

    noise_estimator: MeasurementNoiseEstimator,

    precision_score: i32,
    poll_score: i32,
    desired_poll_interval: PollInterval,

    last_measurement: Measurement,
    prev_was_outlier: bool,

    // Last time a packet was processed
    last_iter: NtpTimestamp,
}

impl SourceFilter {
    /// Move the filter forward to reflect the situation at a new, later timestamp
    fn progress_filtertime(&mut self, time: NtpTimestamp) {
        self.state = self.state.progress_time(time, self.clock_wander);

        trace!(?time, "Filter progressed");
    }

    /// Absorb knowledge from a measurement
    fn absorb_measurement(&mut self, measurement: Measurement) -> (f64, f64, f64) {
        // Measurement parameters
        let m_delta_t = (measurement.localtime - self.last_measurement.localtime).to_seconds();

        // Kalman filter update
        let measurement_vec = Vector::new_vector([measurement.offset.to_seconds()]);
        let measurement_transform = Matrix::new([[1., 0.]]);
        let measurement_noise = match self.noise_estimator {
            MeasurementNoiseEstimator::Constant(v) => Matrix::new([[v]]),
            MeasurementNoiseEstimator::RoundtripDelay(stats) => {
                Matrix::new([[stats.variance() / 4.]])
            }
        };
        let (new_state, stats) = self.state.absorb_measurement(
            measurement_transform,
            measurement_vec,
            measurement_noise,
        );

        self.state = new_state;
        self.last_measurement = measurement;

        trace!(
            stats.observe_probability,
            stats.weight,
            "Measurement absorbed"
        );

        (stats.observe_probability, stats.weight, m_delta_t)
    }

    /// Ensure we poll often enough to keep the filter well-fed with information, but
    /// not so much that each individual poll message gives us very little new information.
    fn update_desired_poll(
        &mut self,
        source_defaults_config: &SourceDefaultsConfig,
        algo_config: &AlgorithmConfig,
        p: f64,
        weight: f64,
        measurement_period: f64,
    ) {
        // We dont want to speed up when we already want more than we get, and vice versa.
        let reference_measurement_period = self.desired_poll_interval.as_duration().to_seconds();
        if weight < algo_config.poll_interval_low_weight
            && measurement_period / reference_measurement_period > 0.75
        {
            self.poll_score -= 1;
        } else if weight > algo_config.poll_interval_high_weight
            && measurement_period / reference_measurement_period < 1.4
        {
            self.poll_score += 1;
        } else {
            self.poll_score -= self.poll_score.signum();
        }
        trace!(poll_score = self.poll_score, ?weight, "Poll desire update");
        if p <= algo_config.poll_interval_step_threshold {
            self.desired_poll_interval = source_defaults_config.poll_interval_limits.min;
            self.poll_score = 0;
        } else if self.poll_score <= -algo_config.poll_interval_hysteresis {
            self.desired_poll_interval = self
                .desired_poll_interval
                .inc(source_defaults_config.poll_interval_limits);
            self.poll_score = 0;
            debug!(interval = ?self.desired_poll_interval, "Increased poll interval");
        } else if self.poll_score >= algo_config.poll_interval_hysteresis {
            self.desired_poll_interval = self
                .desired_poll_interval
                .dec(source_defaults_config.poll_interval_limits);
            self.poll_score = 0;
            debug!(interval = ?self.desired_poll_interval, "Decreased poll interval");
        }
    }

    // Our estimate for the clock stability might be completely wrong. The code here
    // correlates the estimation for errors to what we actually observe, so we can
    // update our estimate should it turn out to be significantly off.
    fn update_wander_estimate(&mut self, algo_config: &AlgorithmConfig, p: f64, weight: f64) {
        // Note that chi is exponentially distributed with mean 2
        // Also, we do not steer towards a smaller precision estimate when measurement noise dominates.
        if 1. - p < algo_config.precision_low_probability
            && weight > algo_config.precision_minimum_weight
        {
            self.precision_score -= 1;
        } else if 1. - p > algo_config.precision_high_probability {
            self.precision_score += 1;
        } else {
            self.precision_score -= self.precision_score.signum();
        }
        trace!(
            precision_score = self.precision_score,
            p,
            "Wander estimate update"
        );
        if self.precision_score <= -algo_config.precision_hysteresis {
            self.clock_wander /= 4.0;
            self.precision_score = 0;
            debug!(
                wander = self.clock_wander.sqrt(),
                "Decreased wander estimate"
            );
        } else if self.precision_score >= algo_config.precision_hysteresis {
            self.clock_wander *= 4.0;
            self.precision_score = 0;
            debug!(
                wander = self.clock_wander.sqrt(),
                "Increased wander estimate"
            );
        }
    }

    /// Update our estimates based on a new measurement.
    fn update(
        &mut self,
        source_defaults_config: &SourceDefaultsConfig,
        algo_config: &AlgorithmConfig,
        measurement: Measurement,
    ) -> bool {
        // Always update the root_delay, root_dispersion, leap second status and stratum, as they always represent the most accurate state.
        self.last_measurement.root_delay = measurement.root_delay;
        self.last_measurement.root_dispersion = measurement.root_dispersion;
        self.last_measurement.stratum = measurement.stratum;
        self.last_measurement.leap = measurement.leap;

        if measurement.localtime.is_before(self.state.time) {
            // Ignore the past
            return false;
        }

        // This was a valid measurement, so no matter what this represents our current iteration time
        // for the purposes of synchronizing
        self.last_iter = measurement.localtime;

        // Filter out one-time outliers (based on delay!)
        if let MeasurementNoiseEstimator::RoundtripDelay(roundtriptime_stats) = self.noise_estimator
        {
            if let Some(delay) = measurement.delay {
                if !self.prev_was_outlier
                    && (delay.to_seconds() - roundtriptime_stats.mean())
                        > algo_config.delay_outlier_threshold
                            * roundtriptime_stats.variance().sqrt()
                {
                    self.prev_was_outlier = true;
                    return false;
                }
            }
        }

        // Environment update
        self.progress_filtertime(measurement.localtime);
        if let MeasurementNoiseEstimator::RoundtripDelay(mut roundtriptime_stats) =
            self.noise_estimator
        {
            if let Some(delay) = measurement.delay {
                roundtriptime_stats.update(delay.to_seconds());
            }
        }

        let (p, weight, measurement_period) = self.absorb_measurement(measurement);

        self.update_wander_estimate(algo_config, p, weight);
        self.update_desired_poll(
            source_defaults_config,
            algo_config,
            p,
            weight,
            measurement_period,
        );

        debug!(
            "source offset {}±{}ms, freq {}±{}ppm",
            self.state.offset() * 1000.,
            (self.state.offset_variance()
                + sqr(self.last_measurement.root_dispersion.to_seconds()))
            .sqrt()
                * 1000.,
            self.state.frequency() * 1e6,
            self.state.frequency_variance().sqrt() * 1e6
        );

        true
    }

    fn process_offset_steering(&mut self, steer: f64) {
        self.state = self.state.process_offset_steering(steer);
        self.last_measurement.offset -= NtpDuration::from_seconds(steer);
        self.last_measurement.localtime += NtpDuration::from_seconds(steer);
    }

    fn process_frequency_steering(&mut self, time: NtpTimestamp, steer: f64) {
        self.state = self
            .state
            .process_frequency_steering(time, steer, self.clock_wander);
        self.last_measurement.offset += NtpDuration::from_seconds(
            steer * (time - self.last_measurement.localtime).to_seconds(),
        );
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum SourceStateInner {
    Initial(InitialSourceFilter),
    Stable(SourceFilter),
}

#[derive(Debug, Clone)]
pub(super) struct SourceState(SourceStateInner);

const MIN_DELAY: NtpDuration = NtpDuration::from_exponent(-18);

impl SourceState {
    pub(super) fn new(noise_estimator: MeasurementNoiseEstimator) -> Self {
        SourceState(SourceStateInner::Initial(InitialSourceFilter {
            noise_estimator,
            init_offset: AveragingBuffer::default(),
            last_measurement: None,
            samples: 0,
        }))
    }

    // Returns whether the clock may need adjusting.
    pub fn update_self_using_measurement(
        &mut self,
        source_defaults_config: &SourceDefaultsConfig,
        algo_config: &AlgorithmConfig,
        mut measurement: Measurement,
    ) -> bool {
        // preprocessing
        measurement.delay = match measurement.delay {
            Some(delay) => Some(delay.max(MIN_DELAY)),
            None => Some(MIN_DELAY),
        };

        self.update_self_using_raw_measurement(source_defaults_config, algo_config, measurement)
    }

    fn update_self_using_raw_measurement(
        &mut self,
        source_defaults_config: &SourceDefaultsConfig,
        algo_config: &AlgorithmConfig,
        measurement: Measurement,
    ) -> bool {
        match &mut self.0 {
            SourceStateInner::Initial(filter) => {
                filter.update(measurement);
                if filter.samples == 8 {
                    *self = SourceState(SourceStateInner::Stable(SourceFilter {
                        state: KalmanState {
                            state: Vector::new_vector([filter.init_offset.mean(), 0.]),
                            uncertainty: Matrix::new([
                                [filter.init_offset.variance(), 0.],
                                [0., sqr(algo_config.initial_frequency_uncertainty)],
                            ]),
                            time: measurement.localtime,
                        },
                        clock_wander: sqr(algo_config.initial_wander),
                        noise_estimator: filter.noise_estimator.clone(), // TODO: can this be done without clone?
                        precision_score: 0,
                        poll_score: 0,
                        desired_poll_interval: source_defaults_config.initial_poll_interval,
                        last_measurement: measurement,
                        prev_was_outlier: false,
                        last_iter: measurement.localtime,
                    }));
                    debug!("Initial source measurements complete");
                }
                true
            }
            SourceStateInner::Stable(filter) => {
                // We check that the difference between the localtime and monotonic
                // times of the measurement is in line with what would be expected
                // from recent steering. This check needs to be done here since we
                // need to revert back to the initial state.
                let localtime_difference =
                    measurement.localtime - filter.last_measurement.localtime;
                let monotime_difference = measurement
                    .monotime
                    .abs_diff(filter.last_measurement.monotime);

                if localtime_difference.abs_diff(monotime_difference)
                    > algo_config.meddling_threshold
                {
                    let msg = "Detected clock meddling. Has another process updated the clock?";
                    tracing::warn!(msg);

                    *self = SourceState(SourceStateInner::Initial(InitialSourceFilter {
                        noise_estimator: match filter.noise_estimator {
                            MeasurementNoiseEstimator::RoundtripDelay(_) => {
                                MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer::default())
                            }
                            MeasurementNoiseEstimator::Constant(v) => {
                                MeasurementNoiseEstimator::Constant(v)
                            }
                        },
                        init_offset: AveragingBuffer::default(),
                        last_measurement: None,
                        samples: 0,
                    }));

                    false
                } else {
                    filter.update(source_defaults_config, algo_config, measurement)
                }
            }
        }
    }

    fn snapshot<Index: Copy>(
        &self,
        index: Index,
        config: &AlgorithmConfig,
    ) -> Option<SourceSnapshot<Index>> {
        match &self.0 {
            SourceStateInner::Initial(InitialSourceFilter {
                noise_estimator,
                init_offset,
                last_measurement: Some(last_measurement),
                samples,
            }) if *samples > 0 => {
                let max_roundtrip = match noise_estimator {
                    MeasurementNoiseEstimator::RoundtripDelay(roundtriptime_stats) => {
                        roundtriptime_stats.data[..*samples as usize]
                            .iter()
                            .copied()
                            .fold(None, |v1, v2| {
                                if v2.is_nan() {
                                    v1
                                } else if let Some(v1) = v1 {
                                    Some(v2.max(v1))
                                } else {
                                    Some(v2)
                                }
                            })?
                    }
                    _ => 0.,
                };
                Some(SourceSnapshot {
                    index,
                    source_uncertainty: last_measurement.root_dispersion,
                    source_delay: last_measurement.root_delay,
                    leap_indicator: last_measurement.leap,
                    last_update: last_measurement.localtime,
                    delay: max_roundtrip,
                    state: KalmanState {
                        state: Vector::new_vector([
                            init_offset.data[..*samples as usize]
                                .iter()
                                .copied()
                                .sum::<f64>()
                                / (*samples as f64),
                            0.0,
                        ]),
                        uncertainty: Matrix::new([
                            [max_roundtrip, 0.0],
                            [0.0, INITIALIZATION_FREQ_UNCERTAINTY],
                        ]),
                        time: last_measurement.localtime,
                    },
                    wander: config.initial_wander,
                })
            }
            SourceStateInner::Stable(filter) => Some(SourceSnapshot {
                index,
                state: filter.state,
                wander: filter.clock_wander,
                delay: match filter.noise_estimator {
                    MeasurementNoiseEstimator::RoundtripDelay(roundtriptime_stats) => {
                        roundtriptime_stats.mean()
                    }
                    _ => 0.,
                },
                source_uncertainty: filter.last_measurement.root_dispersion,
                source_delay: filter.last_measurement.root_delay,
                leap_indicator: filter.last_measurement.leap,
                last_update: filter.last_iter,
            }),
            _ => None,
        }
    }

    pub fn get_desired_poll(&self, limits: &PollIntervalLimits) -> PollInterval {
        match &self.0 {
            SourceStateInner::Initial(_) => limits.min,
            SourceStateInner::Stable(filter) => filter.desired_poll_interval,
        }
    }

    pub fn process_offset_steering(&mut self, steer: f64) {
        match &mut self.0 {
            SourceStateInner::Initial(filter) => filter.process_offset_steering(steer),
            SourceStateInner::Stable(filter) => filter.process_offset_steering(steer),
        }
    }

    pub fn process_frequency_steering(&mut self, time: NtpTimestamp, steer: f64) {
        match &mut self.0 {
            SourceStateInner::Initial(_) => {}
            SourceStateInner::Stable(filter) => filter.process_frequency_steering(time, steer),
        }
    }
}

#[derive(Debug)]
pub struct KalmanSourceController<SourceId> {
    index: SourceId,
    state: SourceState,
    algo_config: AlgorithmConfig,
    source_defaults_config: SourceDefaultsConfig,
}

impl<SourceId: Copy> KalmanSourceController<SourceId> {
    pub(super) fn new(
        index: SourceId,
        algo_config: AlgorithmConfig,
        source_defaults_config: SourceDefaultsConfig,
    ) -> Self {
        KalmanSourceController {
            index,
            state: SourceState::new(MeasurementNoiseEstimator::RoundtripDelay(
                AveragingBuffer::default(),
            )),
            algo_config,
            source_defaults_config,
        }
    }
}

impl<SourceId: std::fmt::Debug + Copy + Send + 'static> SourceController
    for KalmanSourceController<SourceId>
{
    type ControllerMessage = KalmanControllerMessage;
    type SourceMessage = KalmanSourceMessage<SourceId>;

    fn handle_message(&mut self, message: Self::ControllerMessage) {
        match message.inner {
            super::KalmanControllerMessageInner::Step { steer } => {
                self.state.process_offset_steering(steer);
            }
            super::KalmanControllerMessageInner::FreqChange { steer, time } => {
                self.state.process_frequency_steering(time, steer)
            }
        }
    }

    fn handle_measurement(&mut self, measurement: Measurement) -> Option<Self::SourceMessage> {
        if self.state.update_self_using_measurement(
            &self.source_defaults_config,
            &self.algo_config,
            measurement,
        ) {
            self.state
                .snapshot(self.index, &self.algo_config)
                .map(|snapshot| KalmanSourceMessage { inner: snapshot })
        } else {
            None
        }
    }

    fn desired_poll_interval(&self) -> PollInterval {
        self.state
            .get_desired_poll(&self.source_defaults_config.poll_interval_limits)
    }

    fn observe(&self) -> super::super::ObservableSourceTimedata {
        self.state
            .snapshot(&self.index, &self.algo_config)
            .map(|snapshot| snapshot.observe())
            .unwrap_or(ObservableSourceTimedata {
                offset: NtpDuration::ZERO,
                uncertainty: NtpDuration::MAX,
                delay: NtpDuration::MAX,
                remote_delay: NtpDuration::MAX,
                remote_uncertainty: NtpDuration::MAX,
                last_update: NtpTimestamp::default(),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::{packet::NtpLeapIndicator, time_types::NtpInstant};

    use super::*;

    #[test]
    fn test_meddling_detection() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(2800),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(source, SourceState(SourceStateInner::Initial(_))));

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));
        source.process_offset_steering(-1800.0);
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(2800),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(source, SourceState(SourceStateInner::Stable(_))));

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));
        source.process_offset_steering(1800.0);
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base + NtpDuration::from_seconds(2800.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(source, SourceState(SourceStateInner::Stable(_))));
    }

    #[test]
    fn test_offset_steering_and_measurements() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));

        source.process_offset_steering(20e-3);
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                .abs()
                < 1e-7
        );

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 0.0,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));

        source.process_offset_steering(20e-3);
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                .abs()
                < 1e-7
        );

        source.update_self_using_raw_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(20e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );

        assert!(
            dbg!((source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                - 20e-3)
                .abs())
                < 1e-7
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency()
                - 20e-6)
                .abs()
                < 1e-7
        );

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([-20e-3, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 0.0,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(-20e-3),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));

        source.process_offset_steering(-20e-3);
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                .abs()
                < 1e-7
        );

        source.update_self_using_raw_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(-20e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );

        assert!(
            dbg!((source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                - -20e-3)
                .abs())
                < 1e-7
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency()
                - -20e-6)
                .abs()
                < 1e-7
        );
    }

    #[test]
    fn test_freq_steering() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([0.0, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(0.0),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        };

        source.process_frequency_steering(base + NtpDuration::from_seconds(5.0), 200e-6);
        assert!((source.state.frequency() - -200e-6).abs() < 1e-10);
        assert!(source.state.offset().abs() < 1e-8);
        assert!((source.last_measurement.offset.to_seconds() - 1e-3).abs() < 1e-8);
        source.process_frequency_steering(base + NtpDuration::from_seconds(10.0), -200e-6);
        assert!(source.state.frequency().abs() < 1e-10);
        assert!((source.state.offset() - -1e-3).abs() < 1e-8);
        assert!((source.last_measurement.offset.to_seconds() - -1e-3).abs() < 1e-8);

        let mut source = SourceState(SourceStateInner::Stable(SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([0.0, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(0.0),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        }));

        source.process_frequency_steering(base + NtpDuration::from_seconds(5.0), 200e-6);
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency()
                - -200e-6)
                .abs()
                < 1e-10
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                .abs()
                < 1e-8
        );
        source.process_frequency_steering(base + NtpDuration::from_seconds(10.0), -200e-6);
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency()
                .abs()
                < 1e-10
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                - -1e-3)
                .abs()
                < 1e-8
        );
    }

    #[test]
    fn test_init() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceState::new(MeasurementNoiseEstimator::RoundtripDelay(
            AveragingBuffer::default(),
        ));
        assert!(source
            .snapshot(0_usize, &AlgorithmConfig::default())
            .is_none());
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(0e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(1e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(2e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(3e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(4e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(5e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(6e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(7e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                - 3.5e-3)
                .abs()
                < 1e-7
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset_variance()
                - 1e-6)
                > 0.
        );
    }

    #[test]
    fn test_steer_during_init() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceState::new(MeasurementNoiseEstimator::RoundtripDelay(
            AveragingBuffer::default(),
        ));
        assert!(source
            .snapshot(0_usize, &AlgorithmConfig::default())
            .is_none());
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(4e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(5e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(6e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(7e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        source.process_offset_steering(4e-3);
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(4e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(5e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(6e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .frequency_variance()
                > 1.0
        );
        source.update_self_using_measurement(
            &SourceDefaultsConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(7e-3),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset()
                - 3.5e-3)
                .abs()
                < 1e-7
        );
        assert!(
            (source
                .snapshot(0_usize, &AlgorithmConfig::default())
                .unwrap()
                .state
                .offset_variance()
                - 1e-6)
                > 0.
        );
    }

    #[test]
    fn test_poll_duration_variation() {
        let config = SourceDefaultsConfig::default();
        let algo_config = AlgorithmConfig {
            poll_interval_hysteresis: 2,
            ..Default::default()
        };

        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([0.0, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(0.0),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        };

        let baseinterval = source.desired_poll_interval.as_duration().to_seconds();
        let pollup = source
            .desired_poll_interval
            .inc(PollIntervalLimits::default());
        source.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval * 2.);
        assert_eq!(source.poll_score, 0);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(source.poll_score, -1);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(source.poll_score, 0);
        assert_eq!(source.desired_poll_interval, pollup);
        source.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval * 3.);
        assert_eq!(source.poll_score, 0);
        assert_eq!(source.desired_poll_interval, pollup);
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval);
        assert_eq!(source.poll_score, 0);
        assert_eq!(source.desired_poll_interval, pollup);
        source.update_desired_poll(&config, &algo_config, 0.0, 0.0, baseinterval * 3.);
        assert_eq!(source.poll_score, 0);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(source.poll_score, -1);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(source.poll_score, 0);
        assert_eq!(source.desired_poll_interval, pollup);
        source.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(source.poll_score, 1);
        assert_eq!(source.desired_poll_interval, pollup);
        source.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(source.poll_score, 0);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval);
        assert_eq!(source.poll_score, -1);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(
            &config,
            &algo_config,
            1.0,
            (algo_config.poll_interval_high_weight + algo_config.poll_interval_low_weight) / 2.,
            baseinterval,
        );
        assert_eq!(source.poll_score, 0);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(source.poll_score, 1);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        source.update_desired_poll(
            &config,
            &algo_config,
            1.0,
            (algo_config.poll_interval_high_weight + algo_config.poll_interval_low_weight) / 2.,
            baseinterval,
        );
        assert_eq!(source.poll_score, 0);
        assert_eq!(
            source.desired_poll_interval,
            PollIntervalLimits::default().min
        );
    }

    #[test]
    fn test_wander_estimation() {
        let algo_config = AlgorithmConfig {
            precision_hysteresis: 2,
            ..Default::default()
        };

        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut source = SourceFilter {
            state: KalmanState {
                state: Vector::new_vector([0.0, 0.]),
                uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
                time: base,
            },
            clock_wander: 1e-8,
            noise_estimator: MeasurementNoiseEstimator::RoundtripDelay(AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            }),
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: Some(NtpDuration::from_seconds(0.0)),
                offset: NtpDuration::from_seconds(0.0),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
        };

        source.update_wander_estimate(&algo_config, 1.0, 0.0);
        assert_eq!(source.precision_score, 0);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(source.precision_score, -1);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(source.precision_score, 0);
        assert!(dbg!((source.clock_wander - 0.25e-8).abs()) < 1e-12);
        source.update_wander_estimate(&algo_config, 0.0, 0.0);
        assert_eq!(source.precision_score, 1);
        assert!(dbg!((source.clock_wander - 0.25e-8).abs()) < 1e-12);
        source.update_wander_estimate(&algo_config, 0.0, 1.0);
        assert_eq!(source.precision_score, 0);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(&algo_config, 0.0, 0.0);
        assert_eq!(source.precision_score, 1);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(
            &algo_config,
            (algo_config.precision_high_probability + algo_config.precision_low_probability) / 2.0,
            0.0,
        );
        assert_eq!(source.precision_score, 0);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(source.precision_score, -1);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
        source.update_wander_estimate(
            &algo_config,
            (algo_config.precision_high_probability + algo_config.precision_low_probability) / 2.0,
            0.0,
        );
        assert_eq!(source.precision_score, 0);
        assert!((source.clock_wander - 1e-8).abs() < 1e-12);
    }
}
