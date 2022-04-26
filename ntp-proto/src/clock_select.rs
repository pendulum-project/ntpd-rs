use crate::peer::{Peer, MAX_DISTANCE};
use crate::{NtpDuration, NtpTimestamp};

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

#[allow(dead_code)]
fn clock_select(
    peers: &[Peer],
    local_clock_time: NtpTimestamp,
    system_poll: NtpDuration,
) -> Option<Vec<SurvivorTuple>> {
    let valid_associations = peers
        .iter()
        .filter(|p| p.accept_synchronization(local_clock_time, system_poll));

    let candidates = construct_candidate_list(valid_associations, local_clock_time);

    let mut survivors = construct_survivors(&candidates, local_clock_time);

    if survivors.len() < MIN_INTERSECTION_SURVIVORS {
        return None;
    }

    let _system_selection_jitter = cluster_algorithm(&mut survivors);

    Some(survivors)
}

/// Observation: Chrony (sources.c, SRC_SelectSource, line ~920) does not use the Middle tag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
enum EndpointType {
    Upper = 1,
    Middle = 0,
    Lower = -1,
}

#[allow(dead_code)]
#[derive(Debug)]
struct CandidateTuple<'a> {
    peer: &'a Peer,
    endpoint_type: EndpointType,
    /// Correctness interval edge
    edge: NtpDuration,
}

#[allow(dead_code)]
fn construct_candidate_list<'a>(
    valid_associations: impl IntoIterator<Item = &'a Peer>,
    local_clock_time: NtpTimestamp,
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

#[allow(dead_code)]
struct SurvivorTuple<'a> {
    peer: &'a Peer,
    metric: NtpDuration,
}

/// Collect the candidates within the correctness interval
fn construct_survivors<'a>(
    chime_list: &[CandidateTuple<'a>],
    local_clock_time: NtpTimestamp,
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
    local_clock_time: NtpTimestamp,
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
        let metric = MAX_DISTANCE * peer.last_packet.stratum + peer.root_distance(local_clock_time);

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
        let mut qmax_index = 0;
        let mut min_peer_jitter: f64 = 2.0e9;
        let mut max_selection_jitter = -2.0e9;

        for (index, candidate) in candidates.iter().enumerate() {
            let p = candidate.peer;

            min_peer_jitter = f64::min(min_peer_jitter, p.statistics.jitter);

            let selection_jitter_sum = candidates
                .iter()
                .map(|q| p.statistics.offset - q.peer.statistics.offset)
                .map(|delta| delta.to_seconds().powi(2))
                .sum::<f64>();

            let selection_jitter = (selection_jitter_sum / ((candidates.len() - 1) as f64)).sqrt();

            if selection_jitter > max_selection_jitter {
                qmax_index = index;
                max_selection_jitter = selection_jitter;
            }
        }

        // If the maximum selection jitter is less than the minimum peer jitter,
        // Then subsequent iterations will not will not lower the minimum peer jitter,
        // so we might as well stop.
        //
        // To make sure a few survivors are left for the clustering algorithm to chew on, we stop
        // if the number of survivors is less than or equal to NMIN (3).
        if max_selection_jitter < min_peer_jitter || candidates.len() <= MIN_CLUSTER_SURVIVORS {
            // the final version of max_selection_jitter (psi_max in the spec) is
            // stored under the name "system selection jitter" (PSI_s)
            return max_selection_jitter;
        }

        // delete the survivor qmax (the one with the highest jitter) and go around again
        candidates.remove(qmax_index);
    }
}

#[allow(dead_code)]
struct ClockCombine {
    system_offset: NtpDuration,
    system_jitter: NtpDuration,
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
#[allow(dead_code)]
fn clock_combine<'a>(
    survivors: &'a [SurvivorTuple<'a>],
    selection_jitter: NtpDuration,
    local_clock_time: NtpTimestamp,
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
        (selection_jitter.to_seconds().powi(2) + system_peer_jitter.powi(2)).sqrt(),
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
        peers.push(Peer::test_peer())
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
    let survivors = construct_survivors(&candidates, NtpTimestamp::from_fixed_int(0));

    // check that if we find a cluster, it contains more than half of the peers we work with.
    assert!(survivors.is_empty() || 2 * survivors.len() > spec.len());
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn find_interval_simple() {
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_outlier() {
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 2);
    }

    #[test]
    fn find_interval_low_precision_edgecase() {
        // One larger interval whose middle does not lie in
        // both smaller intervals, but whose middles do overlap.
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_interleaving_edgecase() {
        // Three partially overlapping intervals, where
        // the outer center's are not in each others interval.
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 3);
    }

    #[test]
    fn find_interval_no_consensus() {
        // Three disjoint intervals
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn find_interval_tiling() {
        // Three intervals whose midpoints are not in any of the others
        // but which still overlap somewhat.
        let peer_1 = Peer::test_peer();
        let peer_2 = Peer::test_peer();
        let peer_3 = Peer::test_peer();

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

        let survivors = construct_survivors(&intervals, NtpTimestamp::from_fixed_int(0));
        assert_eq!(survivors.len(), 0);
    }

    #[test]
    fn test_construct_candidate_list() {
        let mut peer1 = Peer::test_peer();
        let mut peer2 = Peer::test_peer();

        peer1.statistics.delay = NtpDuration::from_seconds(1.0);

        // delay chosen so the two intervals intersect
        peer2.statistics.delay = NtpDuration::from_seconds(3.0);
        peer2.statistics.offset = NtpDuration::from_seconds(1.5);

        let local_clock_time = NtpTimestamp::ZERO;
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
}
