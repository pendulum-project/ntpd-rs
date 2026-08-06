pub(crate) trait FloatPolyfill {
    fn sqrt(self) -> Self;
    fn powi(self, n: i32) -> Self;
    fn rem_euclid(self, modulus: Self) -> Self;
}

impl FloatPolyfill for f64 {
    fn sqrt(self) -> Self {
        libm::sqrt(self)
    }

    fn powi(self, n: i32) -> Self {
        libm::pow(self, n as f64)
    }

    fn rem_euclid(self, modulus: Self) -> Self {
        let remainder = self % modulus;
        if remainder < 0.0 {
            modulus + remainder
        } else {
            remainder
        }
    }
}
