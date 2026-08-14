use crate::{Clock, ClockId, Direction, Duration, LeapStatus, TAI, Timestamp};

/// A controller for clocks in a system.
pub trait Controller {
    /// Type of clocks which are managed by this controller
    type Clock: Clock;
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
