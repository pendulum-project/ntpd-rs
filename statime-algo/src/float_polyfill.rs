pub(crate) trait FloatPolyfill {
    fn sqrt(self) -> Self;
    fn powi(self, n: i32) -> Self;
}

impl FloatPolyfill for f64 {
    fn sqrt(self) -> Self {
        libm::sqrt(self)
    }

    fn powi(self, n: i32) -> Self {
        libm::pow(self, n as f64)
    }
}
