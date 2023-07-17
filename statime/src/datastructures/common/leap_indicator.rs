#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeapIndicator {
    #[default]
    NoLeap,
    /// the last minute of the current UTC day contains 61 seconds.
    Leap61,
    /// the last minute of the current UTC day contains 59 seconds.
    Leap59,
}
