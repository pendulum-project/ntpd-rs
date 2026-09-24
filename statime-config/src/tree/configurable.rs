use crate::tree::setting::Setting;

/// Relates a configuration type to how it is represented while a configuration
/// is still being loaded.
///
/// This is what lets every field of a partial struct be written the same way,
/// as `<FieldType as Configurable>::Node`, without knowing whether the field
/// holds an atomic value or a nested struct: the type itself answers that.
pub trait Configurable {
    /// How this type is represented before defaults are applied.
    type Partial;

    /// How a field of this type is stored in the partial struct holding it.
    /// Atomic values are stored in a [`Setting`], nested structs in a
    /// [`Section`](crate::tree::section::Section).
    type Node;
}

/// A vector is atomic for merging, so it is stored in a single setting, while
/// its elements stay partial so that they can be defaulted individually.
impl<T> Configurable for Vec<T>
where
    T: Configurable,
{
    type Partial = Vec<T::Partial>;
    type Node = Setting<Vec<T::Partial>>;
}
