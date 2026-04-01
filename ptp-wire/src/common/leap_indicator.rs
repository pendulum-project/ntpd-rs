/// Describes upcoming leap seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LeapIndicator {
    #[default]
    /// No leap seconds will be added or removed on this UTC day.
    NoLeap,
    /// The last minute of the current UTC day contains 61 seconds.
    Leap61,
    /// The last minute of the current UTC day contains 59 seconds.
    Leap59,
}
