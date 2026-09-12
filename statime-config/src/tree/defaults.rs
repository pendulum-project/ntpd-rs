/// Fills in the built-in defaults of everything that is still unset after
/// merging.
pub trait ApplyDefaults {
    fn apply_defaults(&mut self);
}

impl<T> ApplyDefaults for Vec<T>
where
    T: ApplyDefaults,
{
    fn apply_defaults(&mut self) {
        for element in self {
            element.apply_defaults();
        }
    }
}
