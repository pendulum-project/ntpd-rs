use super::*;

#[test]
fn test_kalman_filter_state_new() {
    let kf = KalmanFilterState::new();
    assert_eq!(kf.D, 0.0);
    assert_eq!(kf.w, 0.0);
    assert_eq!(kf.P, [[1.0, 0.0], [0.0, 1.0]]);
}

#[test]
fn test_kalman_filter_predict() {
    let mut kf = KalmanFilterState::new();
    kf.predict(1.0, 1.0);
    assert!(kf.D > 0.0); // Check if the state has been predicted (D should increase)
    assert!(kf.P[0][0] > 1.0); // Check if the covariance has increased
}

#[test]
fn test_kalman_filter_update() {
    let mut kf = KalmanFilterState::new();
    kf.predict(1.0, 1.0);
    kf.update(1.0, 1.0, 1.0);
    assert!(kf.D > 0.0); // Check if the state has been updated
    assert!(kf.P[0][0] < 2.0); // Check if the covariance has decreased after update
}