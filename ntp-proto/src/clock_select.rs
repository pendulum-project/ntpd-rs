use crate::peer::{PeerSnapshot, MAX_DISTANCE};
use crate::time_types::NtpInstant;
use crate::{NtpDuration, PollInterval};

// TODO this should be 4 in production?!
/// Minimum number of survivors needed to be able to discipline the system clock.
/// More survivors (so more servers from which to get the time) means a more accurate time.
///
/// The spec notes (CMIN was renamed to MIN_INTERSECTION_SURVIVORS in our implementation):
///
/// > CMIN defines the minimum number of servers consistent with the correctness requirements.
/// > Suspicious operators would set CMIN to ensure multiple redundant servers are available for the
/// > algorithms to mitigate properly. However, for historic reasons the default value for CMIN is one.
const MIN_INTERSECTION_SURVIVORS: usize = 1;

/// Number of survivors that the cluster_algorithm tries to keep.
///
/// The code skeleton notes that the goal is to give the cluster algorithm something to chew on.
/// The spec itself does not say anything about how this variable is chosen, or why it exists
/// (but it does define the use of this variable)
///
/// Because the input can have fewer than 3 survivors, the MIN_CLUSTER_SURVIVORS
/// is not an actual lower bound on the number of survivors.
const MIN_CLUSTER_SURVIVORS: usize = 3;

pub fn filter_and_combine(
    peers: &[PeerSnapshot],
    local_clock_time: NtpInstant,
    system_poll: PollInterval,
) -> Option<ClockCombine> {
    let selection = clock_select(peers, local_clock_time, system_poll)?;

    let combined = clock_combine(
        &selection.survivors,
        selection.system_selection_jitter,
        local_clock_time,
    );

    Some(combined)
}

struct ClockSelect<'a> {
    survivors: Vec<SurvivorTuple<'a>>,
    system_selection_jitter: NtpDuration,
}

fn clock_select(
    peers: &[PeerSnapshot],
    local_clock_time: NtpInstant,
    system_poll: PollInterval,
) -> Option<ClockSelect> {
    let valid_associations = peers.iter().filter(|p| {
        p.accept_synchronization(local_clock_time, system_poll)
            .is_ok()
    });

    let candidates = construct_candidate_list(valid_associations, local_clock_time);

    let mut survivors = construct_survivors(&candidates, local_clock_time);

    if survivors.len() < MIN_INTERSECTION_SURVIVORS {
        return None;
    }

    let system_selection_jitter = NtpDuration::from_seconds(cluster_algorithm(&mut survivors));

    Some(ClockSelect {
        survivors,
        system_selection_jitter,
    })
}

/// Observation: Chrony (sources.c, SRC_SelectSource, line ~920) does not use the Middle tag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
enum EndpointType {
    Upper = 1,
    Middle = 0,
    Lower = -1,
}

#[derive(Debug)]
struct CandidateTuple<'a> {
    peer: &'a PeerSnapshot,
    endpoint_type: EndpointType,
    /// Correctness interval edge
    edge: NtpDuration,
}

fn construct_candidate_list<'a>(
    valid_associations: impl IntoIterator<Item = &'a PeerSnapshot>,
    local_clock_time: NtpInstant,
) -> Vec<CandidateTuple<'a>> {
    let mut candidate_list = Vec::new();

    for peer in valid_associations {
        let offset = peer.statistics.offset;
        let root_distance = peer.root_distance(local_clock_time);

        let tuples = [
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Lower,
                edge: offset - root_distance,
            },
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Middle,
                edge: offset,
            },
            CandidateTuple {
                peer,
                endpoint_type: EndpointType::Upper,
                edge: offset + root_distance,
            },
        ];

        candidate_list.extend(tuples)
    }

    candidate_list.sort_by(|a, b| a.edge.cmp(&b.edge));

    candidate_list
}

#[derive(Debug, Clone)]
struct SurvivorTuple<'a> {
    peer: &'a PeerSnapshot,
    metric: NtpDuration,
}

/// Collect the candidates within the correctness interval
fn construct_survivors<'a>(
    chime_list: &[CandidateTuple<'a>],
    local_clock_time: NtpInstant,
) -> Vec<SurvivorTuple<'a>> {
    match find_interval(chime_list) {
        Some((low, high)) => chime_list
            .iter()
            .filter_map(|candidate| filter_survivor(candidate, local_clock_time, low, high))
            .collect(),
        None => vec![],
    }
}

fn filter_survivor<'a>(
    candidate: &CandidateTuple<'a>,
    local_clock_time: NtpInstant,
    low: NtpDuration,
    high: NtpDuration,
) -> Option<SurvivorTuple<'a>> {
    // To be a truechimer, a peers middle (actual offset)
    // needs to lie within the consistency interval.
    // Note: The standard is unclear on this, but this
    // is what gives sensible results in combination with
    // how interval selection works.
    if candidate.edge < low
        || candidate.edge > high
        || candidate.endpoint_type != EndpointType::Middle
    {
        None
    } else {
        let peer = candidate.peer;
        let metric = MAX_DISTANCE * peer.stratum + peer.root_distance(local_clock_time);

        Some(SurvivorTuple { peer, metric })
    }
}

/// Find the largest contiguous intersection of correctness intervals.
fn find_interval(chime_list: &[CandidateTuple]) -> Option<(NtpDuration, NtpDuration)> {
    let n = chime_list.len() / 3;

    let mut low = None;
    let mut high = None;

    // allow is the number of allowed falsetickers
    for allow in (0..).take_while(|allow| 2 * allow < n) {
        // variable "d", falsetickers found in the current iteration
        let mut found = 0;

        // variable "c", the number of intervals that we have entered but not yet exited
        // incremented when hitting a Lower, decremented when hitting an Upper
        let mut depth = 0;

        // Scan the chime list from lowest to highest to find the lower endpoint.
        // any middle that we find before the lower endpoint counts as a falseticker
        for tuple in chime_list {
            depth -= tuple.endpoint_type as i32;

            // the code skeleton uses `n - found` here, which is wrong!
            if depth >= (n - allow) as i32 {
                low = Some(tuple.edge);
                break;
            }

            if let EndpointType::Middle = tuple.endpoint_type {
                found += 1;
            }
        }

        // Scan the chime list from highest to lowest to find the upper endpoint.
        // any middle that we find before the upper endpoint counts as a falseticker
        depth = 0;
        for tuple in chime_list.iter().rev() {
            depth += tuple.endpoint_type as i32;

            // the code skeleton uses `n - found` here, which is wrong!
            if depth >= (n - allow) as i32 {
                high = Some(tuple.edge);
                break;
            }

            if let EndpointType::Middle = tuple.endpoint_type {
                found += 1;
            }
        }

        // counted more falsetickers than allowed in this iteration;
        // we loop and try again allowing one more falseticker
        if found > allow {
            continue;
        }

        //  If the intersection is non-empty, declare success.
        if let (Some(l), Some(h)) = (low, high) {
            return Some((l, h));
        }
    }

    None
}

/// Discard the survivor with maximum selection jitter until a termination condition is met.
///
/// returns the (maximum) selection jitter
fn cluster_algorithm(candidates: &mut Vec<SurvivorTuple>) -> f64 {
    // sort the candidates by increasing lambda_p (the merit factor)
    candidates.sort_by(|a, b| a.metric.cmp(&b.metric));

    loop {
        // the lowest jitter of any candidate peer
        let mut min_peer_jitter: f64 = 2.0e9;

        // highest RMS average of the `offset` of a candidate vs all others
        // the candidate with the max_selection_jitter is the worst candidate
        // we have seen so far, it's offset is most unlike the others.
        let mut max_selection_jitter = -2.0e9;
        let mut max_selection_jitter_index = 0;

        for (index, candidate) in candidates.iter().enumerate() {
            let p = candidate.peer;

            min_peer_jitter = f64::min(min_peer_jitter, p.statistics.jitter);

            let selection_jitter_sum = candidates
                .iter()
                .map(|q| p.statistics.offset - q.peer.statistics.offset)
                .map(|delta| delta.to_seconds().powi(2))
                .sum::<f64>();

            // prevent a division by 0 if there is just 1 candidate
            let selection_jitter = if selection_jitter_sum == 0.0 {
                0.0
            } else {
                (selection_jitter_sum / ((candidates.len() - 1) as f64)).sqrt()
            };

            if selection_jitter > max_selection_jitter {
                max_selection_jitter_index = index;
                max_selection_jitter = selection_jitter;
            }
        }

        // the maximum jitter among our current set of candidates (selection jitter) is less than
        // the smallest jitter of an individual peer.

        // If the maximum selection jitter is less than the minimum peer jitter,
        // Then subsequent iterations will not will not lower the minimum peer jitter,
        // so we might as well stop.
        let removed_bad_candidates = max_selection_jitter < min_peer_jitter;

        // To make sure a few survivors are left for the clustering algorithm to chew on, we stop
        // if the number of survivors is less than or equal to NMIN (3).
        let too_few_survivors = candidates.len() <= MIN_CLUSTER_SURVIVORS;

        if removed_bad_candidates || too_few_survivors {
            // the final version of max_selection_jitter (psi_max in the spec) is
            // stored under the name "system selection jitter" (PSI_s)

            // Jitter is defined as the root-mean-square (RMS) average of the most recent offset differences
            // RMS always produces a positive number, but our `max_selection_jitter` is negative.
            // In the case of 0 candidates, bound max_selection_jitter from below
            return f64::max(0.0, max_selection_jitter);
        }

        // delete the survivor qmax (the one with the highest jitter) and go around again
        candidates.remove(max_selection_jitter_index);
    }
}

#[derive(Debug)]
pub struct ClockCombine {
    pub system_offset: NtpDuration,
    pub system_jitter: NtpDuration,
}

/// Combine the offsets of the clustering algorithm survivors
/// using a weighted average with weight determined by the root
/// distance.  Compute the selection jitter as the weighted RMS
/// difference between the first survivor and the remaining
/// survivors.  In some cases, the inherent clock jitter can be
/// reduced by not using this algorithm, especially when frequent
/// clockhopping is involved.  The reference implementation can
/// be configured to avoid this algorithm by designating a
/// preferred peer.
///
/// Assumption: the survivors are the output of the clustering algorithm,
/// in particular they are in the order produced by the clustering algorithm.
fn clock_combine<'a>(
    survivors: &'a [SurvivorTuple<'a>],
    system_selection_jitter: NtpDuration,
    local_clock_time: NtpInstant,
) -> ClockCombine {
    let mut y = 0.0; // normalization factor
    let mut z = 0.0; // weighed offset sum

    for tuple in survivors {
        let peer = tuple.peer;
        let x = peer.root_distance(local_clock_time).to_seconds();
        y += 1.0 / x;
        z += peer.statistics.offset.to_seconds() / x;
    }

    let system_offset = NtpDuration::from_seconds(z / y);

    // deviation: the code skeleton does some weird statistics here.
    // we just pick the jitter of the peer that will become the system peer
    // this may be an overestimate but that is not a problem
    let system_peer_jitter = survivors[0].peer.statistics.jitter;

    let system_jitter = NtpDuration::from_seconds(
        (system_selection_jitter.to_seconds().powi(2) + system_peer_jitter.powi(2)).sqrt(),
    );

    ClockCombine {
        system_offset,
        system_jitter,
    }
}

#[cfg(feature = "fuzz")]
pub fn fuzz_find_interval(spec: &[(i64, u64)]) {
    let mut peers = vec![];
    for _ in 0..spec.len() {
        peers.push(test_peer_snapshot())
    }
    let mut candidates = vec![];
    for (i, (center, size)) in spec.iter().enumerate() {
        let size = (*size)
            .min((std::i64::MAX as u64).wrapping_sub(*center as u64))
            .max((*center as u64).wrapping_sub(std::i64::MIN as u64));
        candidates.push(CandidateTuple {
            peer: &peers[i],
            endpoint_type: EndpointType::Lower,
            edge: NtpDuration::from_fixed_int((*center).wrapping_sub(size as i64)),
        });
        candidates.push(CandidateTuple {
            peer: &peers[i],
            endpoint_type: EndpointType::Middle,
            edge: NtpDuration::from_fixed_int(*center),
        });
        candidates.push(CandidateTuple {
            peer: &peers[i],
            endpoint_type: EndpointType::Upper,
            edge: NtpDuration::from_fixed_int((*center).wrapping_add(size as i64)),
        });
    }
    candidates.sort_by(|a, b| a.edge.cmp(&b.edge));
    let survivors = construct_survivors(&candidates, crate::NtpInstant::ZERO);

    // check that if we find a cluster, it contains more than half of the peers we work with.
    assert!(survivors.is_empty() || 2 * survivors.len() > spec.len());
}

#[cfg(any(test, feature = "fuzz"))]
fn test_peer_snapshot() -> PeerSnapshot {
    peer_snapshot(
        crate::peer::PeerStatistics::default(),
        NtpDuration::default(),
        NtpDuration::default(),
    )
}

#[cfg(any(test, feature = "fuzz"))]
fn peer_snapshot(
    statistics: crate::peer::PeerStatistics,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
) -> PeerSnapshot {
    let root_distance_without_time = NtpDuration::MIN_DISPERSION.max(root_delay + statistics.delay)
        / 2i64
        + root_dispersion
        + statistics.dispersion;

    PeerSnapshot {
        time: NtpInstant::ZERO,
        statistics,
        stratum: 0,
        root_distance_without_time,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::peer::PeerStatistics;

    #[test]
    fn clock_combine_simple() {
        let peer_1 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(0),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.1),
            NtpDuration::from_seconds(0.05),
        );

        let peer_2 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(500000),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.1),
            NtpDuration::from_seconds(0.05),
        );

        let peer_3 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(-500000),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.1),
            NtpDuration::from_seconds(0.05),
        );

        let survivors = vec![
            SurvivorTuple {
                peer: &peer_1,
                metric: NtpDuration::from_fixed_int(0),
            },
            SurvivorTuple {
                peer: &peer_2,
                metric: NtpDuration::from_fixed_int(1),
            },
            SurvivorTuple {
                peer: &peer_3,
                metric: NtpDuration::from_fixed_int(2),
            },
        ];

        let result = clock_combine(
            &survivors,
            NtpDuration::from_seconds(0.05),
            NtpInstant::ZERO,
        );
        assert_eq!(result.system_offset, NtpDuration::from_fixed_int(0));
        assert!(result.system_jitter.to_seconds() >= 0.05);
    }

    #[test]
    fn clock_combine_deemphasize_on_root_distance() {
        let peer_1 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(0),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.1),
            NtpDuration::from_seconds(0.05),
        );

        let peer_2 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(500000),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.5),
            NtpDuration::from_seconds(0.05),
        );

        let peer_3 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(0.1),
                offset: NtpDuration::from_fixed_int(-500000),
                dispersion: NtpDuration::from_seconds(0.05),
                jitter: 0.05,
            },
            NtpDuration::from_seconds(0.1),
            NtpDuration::from_seconds(0.05),
        );

        let survivors = vec![
            SurvivorTuple {
                peer: &peer_1,
                metric: NtpDuration::from_fixed_int(0),
            },
            SurvivorTuple {
                peer: &peer_2,
                metric: NtpDuration::from_fixed_int(1),
            },
            SurvivorTuple {
                peer: &peer_3,
                metric: NtpDuration::from_fixed_int(2),
            },
        ];

        let result = clock_combine(
            &survivors,
            NtpDuration::from_seconds(0.05),
            NtpInstant::ZERO,
        );
        assert!(result.system_offset < NtpDuration::from_fixed_int(0));
        assert!(result.system_offset > NtpDuration::from_fixed_int(-500000));
        assert!(result.system_jitter.to_seconds() >= 0.05);
    }

    #[test]
    fn find_interval_simple() {
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(4),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-2),
                NtpDuration::from_fixed_int(2)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_outlier() {
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(15),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(16),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(17),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(2)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn find_interval_low_precision_edgecase() {
        // One larger interval whose middle does not lie in
        // both smaller intervals, but whose middles do overlap.
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-10),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(6),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(5)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_interleaving_edgecase() {
        // Three partially overlapping intervals, where
        // the outer center's are not in each others interval.
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-5),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
        ];

        assert_eq!(
            find_interval(&intervals),
            Some((
                NtpDuration::from_fixed_int(-3),
                NtpDuration::from_fixed_int(3)
            ))
        );

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_no_consensus() {
        // Three disjoint intervals
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-4),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(4),
            },
        ];

        assert_eq!(find_interval(&intervals), None);

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn find_interval_tiling() {
        // Three intervals whose midpoints are not in any of the others
        // but which still overlap somewhat.
        let peer_1 = test_peer_snapshot();
        let peer_2 = test_peer_snapshot();
        let peer_3 = test_peer_snapshot();

        let intervals = [
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-5),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-3),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(-2),
            },
            CandidateTuple {
                peer: &peer_1,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(-1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(-0),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Lower,
                edge: NtpDuration::from_fixed_int(1),
            },
            CandidateTuple {
                peer: &peer_2,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(2),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Middle,
                edge: NtpDuration::from_fixed_int(3),
            },
            CandidateTuple {
                peer: &peer_3,
                endpoint_type: EndpointType::Upper,
                edge: NtpDuration::from_fixed_int(5),
            },
        ];

        assert_eq!(find_interval(&intervals), None);

        let survivors = construct_survivors(&intervals, NtpInstant::ZERO);
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn test_construct_candidate_list() {
        let root_delay = NtpDuration::ZERO;
        let root_dispersion = NtpDuration::ZERO;

        let peer1 = peer_snapshot(
            PeerStatistics {
                delay: NtpDuration::from_seconds(1.0),
                ..PeerStatistics::default()
            },
            root_delay,
            root_dispersion,
        );
        let peer2 = peer_snapshot(
            PeerStatistics {
                // delay chosen so the two intervals intersect
                delay: NtpDuration::from_seconds(3.0),
                offset: NtpDuration::from_seconds(1.5),
                ..PeerStatistics::default()
            },
            root_delay,
            root_dispersion,
        );

        let local_clock_time = NtpInstant::ZERO;
        let actual: Vec<_> = construct_candidate_list([&peer1, &peer2], local_clock_time)
            .into_iter()
            .map(|t| (t.endpoint_type, t.edge))
            .collect();

        let root_distance1 = peer1.root_distance(local_clock_time);
        let root_distance2 = peer2.root_distance(local_clock_time);

        assert_eq!(root_distance1, peer1.statistics.delay / 2i64);
        assert_eq!(root_distance2, peer2.statistics.delay / 2i64);

        assert!((root_distance1.to_seconds() - 0.5).abs() < 1e-9);
        assert!((root_distance2.to_seconds() - 1.5).abs() < 1e-9);

        // the interval is the offset plus/minus the root distance.
        //
        // - interval 1 is centered on 0, going 0.5 to either side.     -0.5 -- 0.0 -- 0.5
        // - interval 2 is centered on 1.5, going 1.5 to either side            0.0 --     -- 1.5 --    -- 3.0
        //
        // in practice, interval2.low < interval2.middle because of imprecision in the calculation
        use EndpointType::*;
        let expected: Vec<(EndpointType, NtpDuration)> = vec![
            (Lower, peer1.statistics.offset - root_distance1),
            (Lower, peer2.statistics.offset - root_distance2),
            (Middle, peer1.statistics.offset),
            (Upper, peer1.statistics.offset + root_distance1),
            (Middle, peer2.statistics.offset),
            (Upper, peer2.statistics.offset + root_distance2),
        ];

        assert_eq!(expected, actual)
    }

    #[test]
    fn cluster_algorithm_empty() {
        // this should not happen in practice
        assert_eq!(cluster_algorithm(&mut vec![]), 0.0)
    }

    #[test]
    fn cluster_algorithm_single() {
        let peer = test_peer_snapshot();
        let candidate = SurvivorTuple {
            peer: &peer,
            metric: NtpDuration::ONE,
        };
        assert_eq!(cluster_algorithm(&mut vec![candidate]), 0.0);
    }

    #[test]
    fn cluster_algorithm_tuple() {
        let mut peer1 = test_peer_snapshot();
        peer1.statistics.offset = NtpDuration::ONE * 3i64;
        let candidate1 = SurvivorTuple {
            peer: &peer1,
            metric: NtpDuration::ONE,
        };

        let mut peer2 = test_peer_snapshot();
        peer2.statistics.offset = NtpDuration::ONE * 7i64;
        let candidate2 = SurvivorTuple {
            peer: &peer2,
            metric: NtpDuration::ONE * 3i64,
        };

        let mut candidates = vec![candidate1, candidate2];
        let answer = cluster_algorithm(&mut candidates);

        // output is the RMS of the `statistics.offset` versus candidate1: 4 = 7 - 3
        assert!((answer - 4.0).abs() < 1e-9);

        // we exit before a candidate is removed
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn cluster_algorithm_exit_too_few_candidates() {
        let mut peer1 = test_peer_snapshot();
        peer1.statistics.offset = NtpDuration::ONE * 3i64;
        let candidate1 = SurvivorTuple {
            peer: &peer1,
            metric: NtpDuration::ONE,
        };

        let mut candidates = vec![candidate1; 10];
        let answer = cluster_algorithm(&mut candidates);
        assert!((answer - 0.0).abs() < 1e-9);

        // we keep at least MIN_CLUSTER_SURVIVORS (if we started with enough candidates)
        assert_eq!(candidates.len(), MIN_CLUSTER_SURVIVORS);
    }

    #[test]
    #[ignore]
    fn cluster_algorithm_exit_max_jitter_too_low() {
        // This test shows that the max_selection_jitter can still decrease
        // after the termination condition has been met. That means the spec text and
        // code skeleton comment are at least misleading (and perhaps wrong).

        let mut peer = test_peer_snapshot();
        peer.statistics.offset = NtpDuration::ONE * 3i64;

        let peers = &mut vec![peer; 15];

        for (i, peer) in peers.iter_mut().enumerate() {
            peer.statistics.jitter = 3.0 + 1.0 - (1.0 / (i + 1) as f64);
            peer.statistics.offset = NtpDuration::ONE * (i as i64);
        }

        let mut candidates = (0..15)
            .map(|i| SurvivorTuple {
                peer: &peers[i],
                metric: NtpDuration::ONE,
            })
            .collect();

        let answer = cluster_algorithm(&mut candidates);
        assert!((answer - 2.7386127881634637).abs() < 1e-9);

        assert_eq!(candidates.len(), 5);
        panic!();
    }

    #[test]
    fn cluster_algorithm_outlier_is_discarded_first() {
        let mut peer = test_peer_snapshot();
        peer.statistics.offset = NtpDuration::ONE * 3i64;

        let peers = &mut vec![peer; 4];

        for (i, peer) in peers.iter_mut().enumerate() {
            peer.statistics.jitter = 1.0 - (1.0 / (i + 1) as f64);
            peer.statistics.offset = NtpDuration::ONE;
        }

        peers[2].statistics.offset = NtpDuration::ONE * 4;

        let mut candidates = (0..peers.len())
            .map(|i| SurvivorTuple {
                peer: &peers[i],
                metric: NtpDuration::ONE,
            })
            .collect();

        let _answer = cluster_algorithm(&mut candidates);

        // check that peer 2 was discarded
        assert_eq!(candidates.len(), 3);
        for candidate in candidates {
            assert_eq!(candidate.peer.statistics.offset, NtpDuration::ONE);
        }
    }

    #[test]
    fn cluster_algorithm_outliers_are_discarded_first() {
        let mut peer = test_peer_snapshot();
        peer.statistics.offset = NtpDuration::ONE * 3i64;

        let peers = &mut vec![peer; 5];

        for (i, peer) in peers.iter_mut().enumerate() {
            peer.statistics.jitter = 1.0 - (1.0 / (i + 1) as f64);
            peer.statistics.offset = NtpDuration::ONE;
        }

        peers[2].statistics.offset = NtpDuration::ONE * 4;
        peers[3].statistics.offset = NtpDuration::ONE * 8;

        let mut candidates = (0..peers.len())
            .map(|i| SurvivorTuple {
                peer: &peers[i],
                metric: NtpDuration::ONE,
            })
            .collect();

        let _answer = cluster_algorithm(&mut candidates);

        // check that peer 2 and 3 were
        assert_eq!(candidates.len(), 3);
        for candidate in candidates {
            assert_eq!(candidate.peer.statistics.offset, NtpDuration::ONE);
        }
    }
}
