use crate::SystemConfig;

use super::config::AlgorithmConfig;

pub(super) struct PeerRange {
    pub offset: f64,
    pub uncertainty: f64,
    pub delay: f64,
}

enum BoundType {
    Start,
    End,
}

pub(super) fn select<Index: Copy>(
    config: &SystemConfig,
    algo_config: &AlgorithmConfig,
    candidates: Vec<(Index, PeerRange)>,
) -> Option<Vec<Index>> {
    let mut bounds: Vec<(f64, BoundType)> = Vec::with_capacity(2 * candidates.len());

    for (_, range) in candidates.iter() {
        let range_radius = range.uncertainty * algo_config.range_statistical_weight
            + range.delay * algo_config.range_delay_weight;
        if range_radius > algo_config.max_peer_uncertainty {
            continue;
        }

        bounds.push((range.offset - range_radius, BoundType::Start));
        bounds.push((range.offset + range_radius, BoundType::End));
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
        Some(
            candidates
                .iter()
                .filter_map(|(index, range)| {
                    let range_radius = range.uncertainty * algo_config.range_statistical_weight
                        + range.delay * algo_config.range_delay_weight;
                    if range_radius > algo_config.max_peer_uncertainty {
                        return None;
                    }

                    if range.offset - range_radius <= maxt && range.offset + range_radius >= maxt {
                        Some(*index)
                    } else {
                        None
                    }
                })
                .collect(),
        )
    } else {
        None
    }
}
