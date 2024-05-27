#[derive(Debug, Clone, Copy)]
pub struct KalmanFilterState {
    pub D: f64,
    pub w: f64,
    pub P: [[f64; 2]; 2],
}

impl KalmanFilterState {
    pub fn new() -> Self {
        KalmanFilterState {
            D: 0.0,
            w: 0.0,
            P: [[1.0, 0.0], [0.0, 1.0]],
        }
    }

    pub fn predict(&mut self, delta_t: f64, v: f64) {
        let F = [[1.0, delta_t], [0.0, 1.0]];
        let Q = [
            [v * delta_t.powi(3) / 3.0, v * delta_t.powi(2) / 2.0],
            [v * delta_t.powi(2) / 2.0, v * delta_t],
        ];

        // Predicted state
        self.D += self.w * delta_t;

        // Predicted covariance
        let mut P_new = [[0.0; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    P_new[i][j] += F[i][k] * self.P[k][j];
                }
            }
        }
        let mut P_temp = [[0.0; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    P_temp[i][j] += P_new[i][k] * F[j][k];
                }
            }
        }
        self.P = P_temp;

        // Add process noise
        for i in 0..2 {
            for j in 0..2 {
                self.P[i][j] += Q[i][j];
            }
        }
    }

    pub fn update(&mut self, measurement: f64, delta_t: f64, s: f64) {
        let H = [[1.0, 0.0], [0.0, delta_t]];
        let R = [[s / 4.0, s / 4.0], [s / 4.0, s / 2.0]];

        let y = [measurement - self.D, -self.w * delta_t];

        let mut S = [[0.0; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    S[i][j] += H[i][k] * self.P[k][j];
                }
                S[i][j] += R[i][j];
            }
        }

        let mut K = [[0.0; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    K[i][j] += self.P[i][k] * H[j][k];
                }
                K[i][j] /= S[i][j];
            }
        }

        self.D += K[0][0] * y[0] + K[0][1] * y[1];
        self.w += K[1][0] * y[0] + K[1][1] * y[1];

        let mut P_new = [[0.0; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    P_new[i][j] += (1.0 - K[i][j]) * self.P[i][k];
                }
            }
        }

        self.P = P_new;
    }
}