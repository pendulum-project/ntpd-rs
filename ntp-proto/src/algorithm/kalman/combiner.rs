use crate::{NtpDuration, NtpLeapIndicator};

use super::{
    config::AlgorithmConfig,
    matrix::{Matrix, Vector},
    sqr, PeerSnapshot,
};

pub(super) struct Combine<Index: Copy> {
    pub estimate: Vector,
    pub uncertainty: Matrix,
    pub peers: Vec<Index>,
    pub delay: NtpDuration,
    pub leap_indicator: Option<NtpLeapIndicator>,
}

fn vote_leap<Index: Copy>(selection: &[PeerSnapshot<Index>]) -> Option<NtpLeapIndicator> {
    let mut votes_59 = 0;
    let mut votes_61 = 0;
    let mut votes_none = 0;
    for snapshot in selection {
        match snapshot.leap_indicator {
            NtpLeapIndicator::NoWarning => votes_none += 1,
            NtpLeapIndicator::Leap61 => votes_61 += 1,
            NtpLeapIndicator::Leap59 => votes_59 += 1,
            NtpLeapIndicator::Unknown => {
                panic!("Unsynchronized peer selected for synchronization!")
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
    selection: &[PeerSnapshot<Index>],
    algo_config: &AlgorithmConfig,
) -> Option<Combine<Index>> {
    selection.first().map(|first| {
        let mut estimate = first.state;
        let mut uncertainty = if algo_config.ignore_server_dispersion {
            first.uncertainty
        } else {
            first.uncertainty + Matrix::new(sqr(first.peer_uncertainty.to_seconds()), 0., 0., 0.)
        };

        let mut used_peers = vec![(first.index, uncertainty.determinant())];

        for snapshot in selection.iter().skip(1) {
            let peer_estimate = snapshot.state;
            let peer_uncertainty = if algo_config.ignore_server_dispersion {
                snapshot.uncertainty
            } else {
                snapshot.uncertainty
                    + Matrix::new(sqr(snapshot.peer_uncertainty.to_seconds()), 0., 0., 0.)
            };

            used_peers.push((snapshot.index, peer_uncertainty.determinant()));

            // Merge measurements
            let mixer = (uncertainty + peer_uncertainty).inverse();
            estimate = estimate + uncertainty * mixer * (peer_estimate - estimate);
            uncertainty = uncertainty * mixer * peer_uncertainty;
        }

        used_peers.sort_by(|a, b| a.1.total_cmp(&b.1));

        Combine {
            estimate,
            uncertainty,
            peers: used_peers.iter().map(|v| v.0).collect(),
            delay: selection
                .iter()
                .map(|v| NtpDuration::from_seconds(v.delay) + v.peer_delay)
                .min()
                .unwrap_or(NtpDuration::from_seconds(first.delay) + first.peer_delay),
            leap_indicator: vote_leap(selection),
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::NtpTimestamp;

    use super::*;

    fn snapshot_for_state(
        state: Vector,
        uncertainty: Matrix,
        peer_uncertainty: f64,
    ) -> PeerSnapshot<usize> {
        PeerSnapshot {
            index: 0,
            state,
            uncertainty,
            delay: 0.0,
            peer_uncertainty: NtpDuration::from_seconds(peer_uncertainty),
            peer_delay: NtpDuration::from_seconds(0.01),
            leap_indicator: crate::NtpLeapIndicator::NoWarning,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    #[test]
    fn test_none() {
        let selected: Vec<PeerSnapshot<usize>> = vec![];
        let algconfig = AlgorithmConfig::default();
        assert!(combine(&selected, &algconfig).is_none());
    }

    #[test]
    fn test_single() {
        let selected = vec![snapshot_for_state(
            Vector::new(0.0, 0.0),
            Matrix::new(1e-6, 0.0, 0.0, 1e-12),
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
                Vector::new(0.0, 0.0),
                Matrix::new(1e-6, 0.0, 0.0, 1e-12),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new(1e-3, 0.0),
                Matrix::new(1e-6, 0.0, 0.0, 1e-12),
                1e-3,
            ),
        ];

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.entry(0) - 5e-4).abs() < 1e-8);
        assert!(result.estimate.entry(1).abs() < 1e-8);
        assert!((result.uncertainty.entry(0, 0) - 1e-6).abs() < 1e-12);
        assert!((result.uncertainty.entry(1, 1) - 5e-13).abs() < 1e-16);

        let algconfig = AlgorithmConfig {
            ignore_server_dispersion: true,
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert!((result.estimate.entry(0) - 5e-4).abs() < 1e-8);
        assert!(result.estimate.entry(1).abs() < 1e-8);
        assert!((result.uncertainty.entry(0, 0) - 5e-7).abs() < 1e-12);
        assert!((result.uncertainty.entry(1, 1) - 5e-13).abs() < 1e-16);
    }

    #[test]
    fn test_sort_order() {
        let mut selected = vec![
            snapshot_for_state(
                Vector::new(0.0, 0.0),
                Matrix::new(1e-6, 0.0, 0.0, 1e-12),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new(1e-3, 0.0),
                Matrix::new(2e-6, 0.0, 0.0, 2e-12),
                1e-3,
            ),
        ];
        selected[0].index = 0;
        selected[1].index = 1;

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.peers, vec![0, 1]);

        let mut selected = vec![
            snapshot_for_state(
                Vector::new(1e-3, 0.0),
                Matrix::new(2e-6, 0.0, 0.0, 2e-12),
                1e-3,
            ),
            snapshot_for_state(
                Vector::new(0.0, 0.0),
                Matrix::new(1e-6, 0.0, 0.0, 1e-12),
                1e-3,
            ),
        ];
        selected[0].index = 0;
        selected[1].index = 1;

        let algconfig = AlgorithmConfig {
            ..Default::default()
        };
        let result = combine(&selected, &algconfig).unwrap();
        assert_eq!(result.peers, vec![1, 0]);
    }

    fn snapshot_for_leap(leap: NtpLeapIndicator) -> PeerSnapshot<usize> {
        PeerSnapshot {
            index: 0,
            state: Vector::new(0.0, 0.0),
            uncertainty: Matrix::new(1e-6, 0.0, 0.0, 1e-12),
            delay: 0.0,
            peer_uncertainty: NtpDuration::from_seconds(0.0),
            peer_delay: NtpDuration::from_seconds(0.0),
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
