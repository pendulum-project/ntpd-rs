use crate::{packet::NtpLeapIndicator, time_types::NtpDuration};

use super::{
    config::AlgorithmConfig,
    matrix::{Matrix, Vector},
    sqr, SourceSnapshot,
};

pub(super) struct Combine<Index: Copy> {
    pub estimate: Vector<2>,
    pub uncertainty: Matrix<2, 2>,
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
        let mut uncertainty = if algo_config.ignore_server_dispersion {
            first.uncertainty
        } else {
            first.uncertainty
                + Matrix::new([[sqr(first.source_uncertainty.to_seconds()), 0.], [0., 0.]])
        };

        let mut used_sources = vec![(first.index, uncertainty.determinant())];

        for snapshot in selection.iter().skip(1) {
            let source_estimate = snapshot.state;
            let source_uncertainty = if algo_config.ignore_server_dispersion {
                snapshot.uncertainty
            } else {
                snapshot.uncertainty
                    + Matrix::new([
                        [sqr(snapshot.source_uncertainty.to_seconds()), 0.],
                        [0., 0.],
                    ])
            };

            used_sources.push((snapshot.index, source_uncertainty.determinant()));

            // Merge measurements
            let mixer = (uncertainty + source_uncertainty).inverse();
            estimate = estimate + uncertainty * mixer * (source_estimate - estimate);
            uncertainty = uncertainty * mixer * source_uncertainty;
        }

        used_sources.sort_by(|a, b| a.1.total_cmp(&b.1));

        Combine {
            estimate,
            uncertainty,
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
    use crate::time_types::NtpTimestamp;

    use super::*;

    fn snapshot_for_state(
        state: Vector<2>,
        uncertainty: Matrix<2, 2>,
        source_uncertainty: f64,
    ) -> SourceSnapshot<usize> {
        SourceSnapshot {
            index: 0,
            state,
            uncertainty,
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
        assert!((result.uncertainty.entry(0, 0) - 2e-6).abs() < 1e-12);
        assert!((result.uncertainty.entry(0, 0) - 2e-6).abs() < 1e-12);

        let algconfig = AlgorithmConfig {
            ignore_server_dispersion: true,
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.uncertainty.entry(0, 0) - 1e-6).abs() < 1e-12);
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
        assert!((result.estimate.ventry(0) - 5e-4).abs() < 1e-8);
        assert!(result.estimate.ventry(1).abs() < 1e-8);
        assert!((result.uncertainty.entry(0, 0) - 1e-6).abs() < 1e-12);
        assert!((result.uncertainty.entry(1, 1) - 5e-13).abs() < 1e-16);

        let algconfig = AlgorithmConfig {
            ignore_server_dispersion: true,
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.ventry(0) - 5e-4).abs() < 1e-8);
        assert!(result.estimate.ventry(1).abs() < 1e-8);
        assert!((result.uncertainty.entry(0, 0) - 5e-7).abs() < 1e-12);
        assert!((result.uncertainty.entry(1, 1) - 5e-13).abs() < 1e-16);
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
            state: Vector::new_vector([0.0, 0.0]),
            uncertainty: Matrix::new([[1e-6, 0.0], [0.0, 1e-12]]),
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
