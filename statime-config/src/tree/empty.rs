/// Whether a node carries no information and can be omitted when serializing.
pub trait EffectivelyUnset {
    fn is_effectively_unset(&self) -> bool;
}

/// Helper function for `#[serde(skip_serializing_if = ...)]` on every field of a
/// partial struct.
pub fn is_effectively_unset<T>(value: &T) -> bool
where
    T: EffectivelyUnset,
{
    value.is_effectively_unset()
}
