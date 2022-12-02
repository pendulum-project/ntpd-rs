use crate::SystemConfig;

use super::{config::AlgorithmConfig, PeerSnapshot};

enum BoundType {
    Start,
    End,
}

pub(super) fn select<Index: Copy>(
    config: &SystemConfig,
    algo_config: &AlgorithmConfig,
    candidates: Vec<PeerSnapshot<Index>>,
) -> Vec<PeerSnapshot<Index>> {
    let mut bounds: Vec<(f64, BoundType)> = Vec::with_capacity(2 * candidates.len());

    for snapshot in candidates.iter() {
        let radius = snapshot.offset_uncertainty() * algo_config.range_statistical_weight
            + snapshot.delay * algo_config.range_delay_weight;
        if radius > algo_config.max_peer_uncertainty || !snapshot.leap_indicator.is_synchronized() {
            continue;
        }

        bounds.push((snapshot.offset() - radius, BoundType::Start));
        bounds.push((snapshot.offset() + radius, BoundType::End));
    }

    bounds.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

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

    if max >= config.min_intersection_survivors && max * 4 >= bounds.len() {
        candidates
            .iter()
            .filter(|snapshot| {
                let radius = snapshot.offset_uncertainty() * algo_config.range_statistical_weight
                    + snapshot.delay * algo_config.range_delay_weight;
                radius <= algo_config.max_peer_uncertainty
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
