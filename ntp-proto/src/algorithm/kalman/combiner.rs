use crate::{packet::NtpLeapIndicator, time_types::NtpDuration};

use super::{config::AlgorithmConfig, source::KalmanState, SourceSnapshot};

pub(super) struct Combine<Index: Copy> {
    pub estimate: KalmanState,
    pub sources: Vec<Index>,
    pub delay: NtpDuration,
    pub leap_indicator: Option<NtpLeapIndicator>,
}

fn vote_leap<Index: Copy>(selection: &[SourceSnapshot<Index>]) -> Option<NtpLeapIndicator> {
    let mut votes_59 = 0;
    let mut votes_61 = 0;
    let mut votes_none = 0;
    for snapshot in selection {
        match snapshot.leap_indicator {
            NtpLeapIndicator::NoWarning => votes_none += 1,
            NtpLeapIndicator::Leap61 => votes_61 += 1,
            NtpLeapIndicator::Leap59 => votes_59 += 1,
            NtpLeapIndicator::Unknown => {
                panic!("Unsynchronized source selected for synchronization!")
            }
        }
    }
    if votes_none * 2 > selection.len() {
        Some(NtpLeapIndicator::NoWarning)
    } else if votes_59 * 2 > selection.len() {
        Some(NtpLeapIndicator::Leap59)
    } else if votes_61 * 2 > selection.len() {
        Some(NtpLeapIndicator::Leap61)
    } else {
        None
    }
}

pub(super) fn combine<Index: Copy>(
    selection: &[SourceSnapshot<Index>],
    algo_config: &AlgorithmConfig,
) -> Option<Combine<Index>> {
    selection.first().map(|first| {
        let mut estimate = first.state;
        if !algo_config.ignore_server_dispersion {
            estimate = estimate.add_server_dispersion(first.source_uncertainty.to_seconds());
        }

        let mut used_sources = vec![(first.index, estimate.uncertainty.determinant())];

        for snapshot in selection.iter().skip(1) {
            let source_estimate = if algo_config.ignore_server_dispersion {
                snapshot.state
            } else {
                snapshot
                    .state
                    .add_server_dispersion(snapshot.source_uncertainty.to_seconds())
            };

            used_sources.push((snapshot.index, source_estimate.uncertainty.determinant()));

            estimate = estimate.merge(&source_estimate);
        }

        used_sources.sort_by(|a, b| a.1.total_cmp(&b.1));

        Combine {
            estimate,
            sources: used_sources.iter().map(|v| v.0).collect(),
            delay: selection
                .iter()
                .map(|v| NtpDuration::from_seconds(v.delay) + v.source_delay)
                .min()
                .unwrap_or(NtpDuration::from_seconds(first.delay) + first.source_delay),
            leap_indicator: vote_leap(selection),
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        algorithm::kalman::{
            matrix::{Matrix, Vector},
            source::KalmanState,
        },
        time_types::NtpTimestamp,
    };

    use super::*;

    fn snapshot_for_state(
        state: Vector<2>,
        uncertainty: Matrix<2, 2>,
        source_uncertainty: f64,
    ) -> SourceSnapshot<usize> {
        SourceSnapshot {
            index: 0,
            state: KalmanState {
                state,
                uncertainty,
                time: NtpTimestamp::from_fixed_int(0),
            },
            wander: 0.0,
            delay: 0.0,
            source_uncertainty: NtpDuration::from_seconds(source_uncertainty),
            source_delay: NtpDuration::from_seconds(0.01),
            leap_indicator: NtpLeapIndicator::NoWarning,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    #[test]
    fn test_none() {
        let selected: Vec<SourceSnapshot<usize>> = vec![];
        let algconfig = AlgorithmConfig::default();
        assert!(combine(&selected, &algconfig).is_none());
    }

    #[test]
    fn test_single() {
        let selected = vec![snapshot_for_state(
            Vector::new_vector([0.0, 0.0]),
            Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
            1e-3,
        )];

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.offset_variance() - 2e-6).abs() < 1e-12);

        let algconfig = AlgorithmConfig {
            ignore_server_dispersion: true,
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.offset_variance() - 1e-6).abs() < 1e-12);
    }

    #[test]
    fn test_multiple() {
        let selected = vec![
            snapshot_for_state(
                Vector::new_vector([0.0, 0.0]),
                Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new_vector([1e-3, 0.0]),
                Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
                1e-3,
            ),
        ];

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.offset() - 5e-4).abs() < 1e-8);
        assert!(result.estimate.frequency().abs() < 1e-8);
        assert!((result.estimate.offset_variance() - 1e-6).abs() < 1e-12);
        assert!((result.estimate.frequency_variance() - 5e-13).abs() < 1e-16);

        let algconfig = AlgorithmConfig {
            ignore_server_dispersion: true,
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.offset() - 5e-4).abs() < 1e-8);
        assert!(result.estimate.frequency().abs() < 1e-8);
        assert!((result.estimate.offset_variance() - 5e-7).abs() < 1e-12);
        assert!((result.estimate.frequency_variance() - 5e-13).abs() < 1e-16);
    }

    #[test]
    fn test_sort_order() {
        let mut selected = vec![
            snapshot_for_state(
                Vector::new_vector([0.0, 0.0]),
                Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new_vector([1e-3, 0.0]),
                Matrix::new([[2e-6, 0.0], [0.0, 2e-12]]),
                1e-3,
            ),
        ];
        selected[0].index = 0;
        selected[1].index = 1;

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.sources, vec![0, 1]);

        let mut selected = vec![
            snapshot_for_state(
                Vector::new_vector([1e-3, 0.0]),
                Matrix::new([[2e-6, 0.0], [0.0, 2e-12]]),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new_vector([0.0, 0.0]),
                Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
                1e-3,
            ),
        ];
        selected[0].index = 0;
        selected[1].index = 1;

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.sources, vec![1, 0]);
    }

    fn snapshot_for_leap(leap: NtpLeapIndicator) -> SourceSnapshot<usize> {
        SourceSnapshot {
            index: 0,
            state: KalmanState {
                state: Vector::new_vector([0.0, 0.0]),
                uncertainty: Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
                time: NtpTimestamp::from_fixed_int(0),
            },
            wander: 0.0,
            delay: 0.0,
            source_uncertainty: NtpDuration::from_seconds(0.0),
            source_delay: NtpDuration::from_seconds(0.0),
            leap_indicator: leap,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    #[test]
    fn test_leap_vote() {
        let algconfig = AlgorithmConfig::default();

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::NoWarning),
            snapshot_for_leap(NtpLeapIndicator::NoWarning),
            snapshot_for_leap(NtpLeapIndicator::NoWarning),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, Some(NtpLeapIndicator::NoWarning));

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::Leap59),
            snapshot_for_leap(NtpLeapIndicator::Leap59),
            snapshot_for_leap(NtpLeapIndicator::Leap59),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, Some(NtpLeapIndicator::Leap59));

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::Leap61),
            snapshot_for_leap(NtpLeapIndicator::Leap61),
            snapshot_for_leap(NtpLeapIndicator::Leap61),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, Some(NtpLeapIndicator::Leap61));

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::Leap61),
            snapshot_for_leap(NtpLeapIndicator::Leap59),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, None);

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::NoWarning),
            snapshot_for_leap(NtpLeapIndicator::Leap61),
            snapshot_for_leap(NtpLeapIndicator::Leap61),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, Some(NtpLeapIndicator::Leap61));

        let selected = vec![
            snapshot_for_leap(NtpLeapIndicator::NoWarning),
            snapshot_for_leap(NtpLeapIndicator::Leap59),
            snapshot_for_leap(NtpLeapIndicator::Leap61),
        ];
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.leap_indicator, None);
    }
}
