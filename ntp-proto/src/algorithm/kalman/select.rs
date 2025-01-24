use crate::config::SynchronizationConfig;

use super::{config::AlgorithmConfig, SourceSnapshot};

#[derive(Debug)]
enum BoundType {
    Start,
    End,
}

// Select a maximum overlapping set of candidates. Note that we define overlapping
// to mean that the intersection of the confidence intervals of the entire set of
// candidates to be non-empty. This is different to the NTP reference implementation's
// convention that all centers need to be within each others confidence intervals.
//
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
        if snapshot.period.is_some() {
            // Do not let periodic sources be part of the vote for correct time
            continue;
        }

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

    // Find the intersection of the confidence intervals of the maximum
    // overlapping set. We need this entire interval to properly integrate
    // periodic sources
    let mut maxlow: usize = 0;
    let mut maxhigh: usize = 0;
    let mut maxtlow: f64 = 0.0;
    let mut maxthigh: f64 = 0.0;
    let mut cur: usize = 0;

    for (time, boundtype) in bounds.iter() {
        match boundtype {
            BoundType::Start => {
                cur += 1;
                if cur > maxlow {
                    maxlow = cur;
                    maxtlow = *time;
                }
            }
            BoundType::End => {
                if cur > maxhigh {
                    maxhigh = cur;
                    maxthigh = *time;
                }
                cur -= 1;
            }
        }
    }

    // Check that the lower and upper bound of the intersection agree on how many
    // sources are part of the maximum set. If not, something has seriously gone
    // wrong and we shouldn't steer the clock.
    assert_eq!(maxlow, maxhigh);
    let max = maxlow;

    if max >= synchronization_config.minimum_agreeing_sources && max * 4 > bounds.len() {
        candidates
            .iter()
            .filter(|snapshot| {
                let radius = snapshot.offset_uncertainty() * algo_config.range_statistical_weight
                    + snapshot.delay * algo_config.range_delay_weight;
                radius <= algo_config.maximum_source_uncertainty
                    && snapshot.offset() - radius <= maxthigh
                    && snapshot.offset() + radius >= maxtlow
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
        algorithm::kalman::source::KalmanState,
        packet::NtpLeapIndicator,
        time_types::{NtpDuration, NtpTimestamp},
    };

    use super::super::{
        matrix::{Matrix, Vector},
        sqr,
    };

    use super::*;

    fn snapshot_for_range(
        center: f64,
        uncertainty: f64,
        delay: f64,
        period: Option<f64>,
    ) -> SourceSnapshot<usize> {
        SourceSnapshot {
            index: 0,
            state: KalmanState {
                state: Vector::new_vector([center, 0.0]),
                uncertainty: Matrix::new([[sqr(uncertainty), 0.0], [0.0, 10e-12]]),
                time: NtpTimestamp::from_fixed_int(0),
            },
            wander: 0.0,
            delay,
            period,
            source_uncertainty: NtpDuration::from_seconds(0.01),
            source_delay: NtpDuration::from_seconds(0.01),
            leap_indicator: NtpLeapIndicator::NoWarning,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    #[test]
    fn test_weighing() {
        // Test that there only is sufficient overlap in the below set when
        // both statistical and delay based errors are considered.
        let candidates = vec![
            snapshot_for_range(0.0, 0.01, 0.09, None),
            snapshot_for_range(0.0, 0.09, 0.01, None),
            snapshot_for_range(0.05, 0.01, 0.09, None),
            snapshot_for_range(0.05, 0.09, 0.01, None),
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
            snapshot_for_range(0.0, 1.0, 1.0, None),
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.0, 0.01, 0.01, None),
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
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.5, 0.1, 0.1, None),
            snapshot_for_range(0.5, 0.1, 0.1, None),
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
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.0, 0.1, 0.1, None),
            snapshot_for_range(0.5, 0.1, 0.1, None),
            snapshot_for_range(0.5, 0.1, 0.1, None),
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

    #[test]
    fn test_periodic_is_ignored() {
        let candidates = vec![
            snapshot_for_range(0.0, 0.01, 0.01, None),
            snapshot_for_range(0.0, 0.01, 0.01, Some(1.0)),
            snapshot_for_range(0.0, 0.01, 0.01, Some(1.0)),
            snapshot_for_range(0.0, 0.01, 0.01, Some(1.0)),
            snapshot_for_range(0.5, 0.01, 0.01, None),
            snapshot_for_range(0.5, 0.01, 0.01, None),
            snapshot_for_range(0.5, 0.01, 0.01, Some(1.0)),
        ];
        let algconfig = AlgorithmConfig::default();
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 2,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates.clone());
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].offset(), 0.5);
        let sysconfig = SynchronizationConfig {
            minimum_agreeing_sources: 3,
            ..Default::default()
        };
        let result = select(&sysconfig, &algconfig, candidates);
        assert_eq!(result.len(), 0);
    }
}
