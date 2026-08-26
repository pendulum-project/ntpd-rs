use crate::{Clock, ClockId, Direction, Duration, LeapStatus, TAI, Timestamp};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A controller for clocks in a system.
pub trait Controller {
    /// Type of clocks which are managed by this controller
    type Clock: Clock<TAI>;
    /// Measurement links between clocks belonging to the controller.
    type Link<ControllerRef: AsRef<Self>>: Link<Error = Self::Error>;
    /// Errors returned by the controller
    // FIXME: Change this to the error trait once we have that in statime-algo.
    type Error: core::fmt::Debug;
    /// Configuration for internal clocks
    type ClockConfig;
    /// Configuration for links
    type LinkConfig;
    /// Configuration for tracked links (links on which delay is automatically estimated)
    type TrackedLinkConfig;

    /// Add an internal, steered clock to the controller.
    ///
    /// # Errors
    /// May error if the controller is unable to handle more internal clocks
    fn add_clock(
        &self,
        clock: Self::Clock,
        config: Self::ClockConfig,
    ) -> Result<ClockId, Self::Error>;

    /// Remove an internal, steered clock from the controller
    ///
    /// # Errors
    /// May error if the internal clock in question is not known to the controller.
    fn remove_clock(&self, clock_id: ClockId) -> Result<(), Self::Error>;

    /// Create a measurement link between clocks where the delay and noise from the
    /// link itself are automatically determined.
    ///
    /// The resulting link may need measurement in both directions to succesfully
    /// work
    ///
    /// This is an assocatiated function to allow links to store references to the
    /// controller in a manner most convenient for the user.
    ///
    /// # Errors
    /// May fail if clocks are unknown to the controller, or when both clocks are
    /// external clocks.
    fn create_tracked_link<ControllerRef: AsRef<Self>>(
        this: ControllerRef,
        clock_a: ClockId,
        clock_b: Option<ClockId>,
        config: Self::LinkConfig,
        tracked_config: Self::TrackedLinkConfig,
    ) -> Result<Self::Link<ControllerRef>, Self::Error>;

    /// Create a measurement link between clocks without delay estimation.
    ///
    /// This is an associated function instead of a method to allow links to store
    /// references to the controller in a manner most convenient for the user.
    ///
    /// # Errors
    /// May fail if clocks are unknown to the controller, or when both clocks are
    /// external clocks.
    fn create_untracked_link<ControllerRef: AsRef<Self>>(
        this: ControllerRef,
        clock_a: ClockId,
        clock_b: Option<ClockId>,
        config: Self::LinkConfig,
    ) -> Result<Self::Link<ControllerRef>, Self::Error>;

    /// Get a time snapshot of the synchronization status of a clock.
    ///
    /// # Errors
    /// May fail if the clock is unknown to the controller.
    fn clock_snapshot(&self, clock: ClockId) -> Result<TimeSnapshot, Self::Error>;
}

/// A measurement link between clocks.
pub trait Link {
    /// Errors returned by the controller
    // FIXME: Change this to the error trait once we have that in statime-algo.
    type Error: core::fmt::Debug;

    /// Process a measurement on a connection.
    ///
    /// # Errors
    /// May fail if there are any issues processing the measurement, mostly resulting
    /// from unexpected behavior of the underlying clock.
    fn measurement(
        &self,
        measurement: Measurement,
        direction: Direction,
    ) -> Result<(), Self::Error>;

    /// Update additional time keeping information provided by the remote for this link.
    ///
    /// # Errors
    /// May fail if the link does not contain an external clock.
    fn external_data_update(
        &self,
        root_delay: Duration,
        leap_status: Option<LeapStatus>,
        usable: bool,
    ) -> Result<(), Self::Error>;

    /// Returns whether the link actively contributed to the current time estimates on
    /// the last measurement.
    ///
    /// # Errors
    /// May fail only when something is bugged in the library.
    fn active(&self) -> Result<bool, Self::Error>;

    /// Returns the poll rate needed to get the desired accuracy from this link.
    ///
    /// # Errors
    /// May fail only when something is bugged in the library.
    fn desired_poll_interval(&self) -> Result<Duration, Self::Error>;
}

/// A measurement done on a link.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// The timestamp at which the synchronization signal was sent.
    pub send_timestamp: Timestamp<TAI>,
    /// The timestamp at which the synchronization signal was received.
    pub recv_timestamp: Timestamp<TAI>,
    /// The uncertainty of the timestamps.
    pub uncertainty: Duration,
}

/// Snapshot of the synchronization state of a clock.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeSnapshot {
    /// Precision of the local clock
    pub precision: Duration,
    /// Current root delay
    pub root_delay: Duration,
    /// t=0 for root variance calculation
    pub root_variance_base_time: Timestamp<TAI>,
    /// Constant contribution for root variance
    pub root_variance_base: f64,
    /// Linear (*t) contribution for root variance
    pub root_variance_linear: f64,
    /// Quadratic (*t*t) contribution for root variance
    pub root_variance_quadratic: f64,
    /// Cubic (*t*t*t) contribution for root variance
    pub root_variance_cubic: f64,
    /// Current leap indicator state
    pub leap_indicator: Option<LeapStatus>,
    /// Total amount that the clock has stepped
    pub accumulated_steps: Duration,
    /// Crossing this amount of stepping will cause a Panic
    pub accumulated_steps_threshold: Option<Duration>,
}

impl TimeSnapshot {
    /// Root dispersion at the current time.
    #[must_use]
    pub fn root_dispersion(&self, now: Timestamp<TAI>) -> Duration {
        let t = (now - self.root_variance_base_time).as_seconds();
        // Note: dispersion is the standard deviation, so we need a sqrt here.
        Duration::from_f64_seconds(
            (self.root_variance_base
                + t * self.root_variance_linear
                + t.powi(2) * self.root_variance_quadratic
                + t.powi(3) * self.root_variance_cubic)
                .sqrt(),
        )
    }
}

impl Default for TimeSnapshot {
    fn default() -> Self {
        Self {
            precision: Duration::from_seconds_nanos(0, 1),
            root_delay: Duration::ZERO,
            root_variance_base_time: Timestamp::UNIX_EPOCH,
            root_variance_base: 0.0,
            root_variance_linear: 0.0,
            root_variance_quadratic: 0.0,
            root_variance_cubic: 0.0,
            leap_indicator: None,
            accumulated_steps: Duration::ZERO,
            accumulated_steps_threshold: None,
        }
    }
}
