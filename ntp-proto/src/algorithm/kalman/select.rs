use crate::config::SynchronizationConfig;

use super::{config::AlgorithmConfig, SourceSnapshot};

enum BoundType {
    Start,
    End,
}

// Select a maximum overlapping set of candidates. Note that here we define
// overlapping to mean that any part of their confidence intervals overlaps, instead
// of the NTP convention that all centers need to be within each others confidence
// intervals.
// The advantage of doing this is that the algorithm becomes a lot simpler, and it
// is also statistically more sound. Any difference (larger set of accepted sources)
// can be compensated for if desired by setting tighter bounds on the weights
// determining the confidence interval.

pub(super) fn select<Index: Copy>(
    synchronization_config: &SynchronizationConfig,
    algo_config: &AlgorithmConfig,
    candidates: Vec<SourceSnapshot<Index>>,
) -> Vec<SourceSnapshot<Index>> {
    let mut bounds: Vec<(f64, BoundType)> = Vec::with_capacity(2 * candidates.len());
    
    for snapshot in candidates.iter() {
        let radius = snapshot.offset_uncertainty() * algo_config.range_statistical_weight
            + snapshot.delay * algo_config.range_delay_weight;
        if radius > algo_config.maximum_source_uncertainty
            || !snapshot.leap_indicator.is_synchronized()
        {
            continue;
        }

        bounds.push((snapshot.offset() - radius, BoundType::Start));
        bounds.push((snapshot.offset() + radius, BoundType::End));
    }

    bounds.sort_by(|a, b| a.0.total_cmp(&b.0));

    let mut max: usize = 0;
    let mut maxt: f64 = 0.0;
    let mut cur: usize = 0;

    for (time, boundtype) in bounds.iter() {
        match boundtype {
            BoundType::Start => cur += 1,
            BoundType::End => cur -= 1,
        }
        if cur > max {
            max = cur;
            maxt = *time;
        }
    }
    if max >= synchronization_config.minimum_agreeing_sources && max * 4 > bounds.len() {
        candidates
            .iter()
            .filter(|snapshot| {
                let radius = snapshot.offset_uncertainty() * algo_config.range_statistical_weight
                    + snapshot.delay * algo_config.range_delay_weight;
                radius <= algo_config.maximum_source_uncertainty
                    && snapshot.offset() - radius <= maxt
                    && snapshot.offset() + radius >= maxt
                    && snapshot.leap_indicator.is_synchronized()
            })
            .cloned()
            .collect()
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        packet::NtpLeapIndicator,
        time_types::{NtpDuration, NtpTimestamp},
    };

    use super::super::{
        matrix::{Matrix, Vector},
        sqr,
    };

    use super::*;

    fn snapshot_for_range(center: f64, uncertainty: f64, delay: f64) -> SourceSnapshot<usize> {
        SourceSnapshot {
            index: 0,
            state: Vector::new_vector([center, 0.0]),
            uncertainty: Matrix::new([[sqr(uncertainty), 0.0], [0.0, 10e-12]]),
            delay,
            source_uncertainty: NtpDuration::from_seconds(0.01),
            source_delay: NtpDuration::from_seconds(0.01),
            leap_indicator: NtpLeapIndicator::NoWarning,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    #[test]
    fn test_no_candidates() {
        // Test that no candidates are selected when input is empty.
        let candidates: Vec<SourceSnapshot<usize>> = vec![];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..Default::default()
        };
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_all_rejected_due_to_leap_indicator() {
        // Test that all candidates are rejected if their leap indicator is not synchronized.
        let candidates = vec![
            SourceSnapshot {
                index: 0,
                state: Vector::new_vector([0.0, 0.0]),
                uncertainty: Matrix::new([[sqr(0.01), 0.0], [0.0, 10e-12]]),
                delay: 0.01,
                source_uncertainty: NtpDuration::from_seconds(0.01),
                source_delay: NtpDuration::from_seconds(0.01),
                leap_indicator: NtpLeapIndicator::Unknown,
                last_update: NtpTimestamp::from_fixed_int(0),
            },
            SourceSnapshot {
                index: 1,
                state: Vector::new_vector([0.1, 0.0]),
                uncertainty: Matrix::new([[sqr(0.01), 0.0], [0.0, 10e-12]]),
                delay: 0.01,
                source_uncertainty: NtpDuration::from_seconds(0.01),
                source_delay: NtpDuration::from_seconds(0.01),
                leap_indicator: NtpLeapIndicator::Unknown,
                last_update: NtpTimestamp::from_fixed_int(0),
            },
        ];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..Default::default()
        };
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_overlap_within_bounds() {
        // Test that candidates with sufficient overlap are selected.
        let candidates = vec![
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
        ];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 2,
            ..Default::default()
        };
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_edge_case_uncertainty() {
        // Test edge case where uncertainty is exactly on the boundary.
        let candidates = vec![
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.2, 0.1, 0.1),
        ];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..Default::default()
        };
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 0.2,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 2);
    }


    #[test]
    fn test_weighing() {
        // Test that there only is sufficient overlap in the below set when
        // both statistical and delay based errors are considered.
        let candidates = vec![
            snapshot_for_range(0.0, 0.01, 0.09),
            snapshot_for_range(0.0, 0.09, 0.01),
            snapshot_for_range(0.05, 0.01, 0.09),
            snapshot_for_range(0.05, 0.09, 0.01),
        ];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 4,
            ..Default::default()
        };

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 0.0,
            ..Default::default()
        };

        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 0);

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 0.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 0);

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 1.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_rejection() {
        // Test sources get properly rejected as rejection bound gets tightened.
        let candidates = vec![
            snapshot_for_range(0.0, 1.0, 1.0),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.01, 0.01),
        ];
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..Default::default()
        };

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 3.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 3);

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 0.3,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 2);

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 0.03,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 1);

        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 0.003,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_min_survivors() {
        // Test that minimum number of survivors is correctly tested for.
        let candidates = vec![
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.5, 0.1, 0.1),
            snapshot_for_range(0.5, 0.1, 0.1),
        ];
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 3.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };

        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 3,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 3);

        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 4,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_tie() {
        // Test that in the case of a tie no group is chosen.
        let candidates = vec![
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.0, 0.1, 0.1),
            snapshot_for_range(0.5, 0.1, 0.1),
            snapshot_for_range(0.5, 0.1, 0.1),
        ];
        let algconfig = AlgorithmConfig {
            maximum_source_uncertainty: 3.0,
            range_statistical_weight: 1.0,
            range_delay_weight: 1.0,
            ..Default::default()
        };
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 1,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }
}
