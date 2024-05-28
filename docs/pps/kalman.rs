use nalgebra::{Matrix2, Vector2};

#[derive(Debug, Clone, Copy)]
pub struct KalmanFilterState {
    pub D: f64,
    pub w: f64,
    pub P: Matrix2<f64>,
}

impl KalmanFilterState {
    // D: the estimated offset
    // w: the estimated rate of change of the offset
    // P: the covariance matrix representing the uncertainty of the estimated state
    // Initializes a new KalmanFilterstate instance with default values
    pub fn new() -> Self {
        KalmanFilterState {
            D: 0.0,
            w: 0.0,
            P: Matrix2::identity(),
        }
    }

    /// Predicts the next state of the Kalman filter.
    ///
    /// # Arguments
    ///
    /// * `delta_t` - The elapsed time since the last prediction, in seconds.
    /// * `v` - The process noise variance.
    ///
    /// # Updates
    ///
    /// * `D` - The predicted offset.
    /// * `P` - The updated covariance matrix.
    pub fn predict(&mut self, delta_t: f64, v: f64) {
        let F = Matrix2::new(1.0, delta_t, 0.0, 1.0);
        let Q = Matrix2::new(
            v * delta_t.powi(3) / 3.0, v * delta_t.powi(2) / 2.0,
            v * delta_t.powi(2) / 2.0, v * delta_t,
        )

        // Predicted state
        self.D += self.w * delta_t;

        // Predicted covariance (process noise added)
        self.P = F * self.P * F.transpose() + Q;
    }

    /// Updates the state of the Kalman filter based on a new measurement.
    ///
    /// This method adjusts the state estimates and covariance matrix based on a new measurement.
    /// It computes the Kalman gain, which balances the uncertainty between the predicted state and
    /// the new measurement, and then uses this gain to update the state estimates and covariance matrix.
    ///
    /// # Arguments
    ///
    /// * `measurement` - The new measurement of the offset.
    /// * `delta_t` - The elapsed time since the last measurement, in seconds.
    /// * `s` - The measurement noise variance.
    ///
    /// # Updates
    ///
    /// * `D` - The updated offset.
    /// * `w` - The updated rate of change of the offset.
    /// * `P` - The updated covariance matrix.
    pub fn update(&mut self, measurement: f64, delta_t: f64, s: f64) {
        let H = Matrix2::new(1.0, 0.0, 0.0, delta_t);
        let R = Matrix2::new(s / 4.0, s / 4.0, s/ 4.0, s / 2.0);

        // Compute the innovation y. Difference between the actual and predicted measurement
        let y = Vector2::new(measurement - self.D, self.w * delta_t);

        // Compute the innovation covariance S. Uncertainty of innovation.
        let S = H * self.P * H.transpose() + R;
        // Compute the Kalman gain K. How much the predicted state should be adjusted based on the new measurement
        let K = self.P * H.transpose() * S.try_inverse().unwrap();

        // Update state estimates D and w based on K and innovation
        let correction = K * y;
        self.D += correction[0];
        self.w += correction[1];

        // Alter P to project the updated certainty after this new measurement 
        let I = Matrix2::identity();
        self.P = (I - K * H) * self.P;
    }
}