use super::{
    matrix::{Matrix, Vector},
    SourceSnapshot,
};

pub(crate) fn combine_with_pps<Index: Copy + PartialEq + std::fmt::Debug>(
    pps: SourceSnapshot<Index>,
    candidates: Vec<SourceSnapshot<Index>>,
) -> Vec<SourceSnapshot<Index>> {
    println!(
        "COMBINE WITH PPS: Number of candidates: {}",
        candidates.len()
    );
    for snapshot in &candidates {
        println!(
            "COMBINE PPS uncertainty: {:?}, offset: {:?}",
            snapshot.offset_uncertainty(),
            snapshot.offset()
        );
    }

    let mut results = Vec::new();

    for snapshot in &candidates {
        results.push(snapshot.clone());
        let combined = combine_sources(pps.clone(), snapshot.clone());
        results.push(combined.clone());
    }

    results
}

fn combine_sources<Index: Copy>(
    pps_snapshot: SourceSnapshot<Index>,
    other_snapshot: SourceSnapshot<Index>,
) -> SourceSnapshot<Index> {
    let pps_offset = pps_snapshot.offset();
    let pps_offset_uncertainty = pps_snapshot.offset_uncertainty();
    let other_offset = other_snapshot.offset();
    let other_offset_uncertainty = other_snapshot.offset_uncertainty();

    let full_second_floor = other_offset.floor();
    let full_second_ceil = other_offset.ceil();

    let pps_floor_positive = full_second_floor + pps_offset;
    let pps_floor_negative = full_second_floor - pps_offset;
    let pps_ceil_positive = full_second_ceil + pps_offset;
    let pps_ceil_negative = full_second_ceil - pps_offset;

    let other_minimum = other_offset - other_offset_uncertainty;
    let other_maximum = other_offset + other_offset_uncertainty;

    let floor_positive_diff = (pps_floor_positive - other_minimum).abs();
    let floor_negative_diff = (pps_floor_negative - other_minimum).abs();
    let ceil_positive_diff = (pps_ceil_positive - other_maximum).abs();
    let ceil_negative_diff = (pps_ceil_negative - other_maximum).abs();

    let min_diff = floor_positive_diff
        .min(floor_negative_diff)
        .min(ceil_positive_diff)
        .min(ceil_negative_diff);

    let new_offset;

    if min_diff == floor_positive_diff {
        new_offset = pps_floor_positive;
    } else if min_diff == floor_negative_diff {
        new_offset = pps_floor_negative;
    } else if min_diff == ceil_positive_diff {
        new_offset = pps_ceil_positive;
    } else {
        new_offset = pps_ceil_negative;
    }

    let combined_state =
        Vector::<2>::new([[new_offset], [other_snapshot.get_state_vector().ventry(1)]]);

    let other_uncertainty_matrix = other_snapshot.get_uncertainty_matrix();

    let combined_uncertainty = Matrix::<2, 2>::new([
        [pps_offset_uncertainty, other_uncertainty_matrix.entry(0, 1)],
        [
            other_uncertainty_matrix.entry(1, 0),
            other_uncertainty_matrix.entry(1, 1),
        ],
    ]);

    SourceSnapshot {
        index: other_snapshot.index,
        state: combined_state,
        uncertainty: combined_uncertainty,
        delay: other_snapshot.delay,
        source_uncertainty: other_snapshot.source_uncertainty,
        source_delay: other_snapshot.source_delay,
        leap_indicator: other_snapshot.leap_indicator,
        last_update: other_snapshot.last_update,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::kalman::matrix::{Matrix, Vector};
    use crate::algorithm::kalman::SourceSnapshot;
    use crate::time_types::NtpTimestamp;
    use crate::time_types::NtpDuration;

    // Helper to create the snapshots, to be used in testing
    fn create_snapshot<Index: Copy>(
        index: Index,
        offset: f64,
        offset_uncertainty: f64,
        state_vector: [f64; 2],
        uncertainty_matrix: [[f64; 2]; 2],
    ) -> SourceSnapshot<Index> {
        SourceSnapshot {
            index,
            state: Vector::new_vector(state_vector),
            uncertainty: Matrix::new(uncertainty_matrix),
            delay: 0.0,
            source_uncertainty: NtpDuration::from_seconds(0.0),
            source_delay: NtpDuration::from_seconds(0.0),
            leap_indicator: crate::NtpLeapIndicator::NoWarning,
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    // Tests the combination of PPS when there is only one candidate
    #[test]
    fn test_combine_with_pps_single_candidate() {
        let pps_snapshot = create_snapshot(
            1,
            1.0,
            0.1,
            [1.0, 0.0],
            [[0.1, 0.0], [0.0, 0.1]],
        );

        let candidate_snapshot = create_snapshot(
            2,
            1.2,
            0.2,
            [1.2, 0.0],
            [[0.2, 0.0], [0.0, 0.2]],
        );

        let combined = combine_with_pps(pps_snapshot, vec![candidate_snapshot]);
        assert_eq!(combined.len(), 2);
    }

    // Tests the combination of PPS when there are multiple candidates
    #[test]
    fn test_combine_with_pps_multiple_candidates() {
        let pps_snapshot = create_snapshot(
            1,
            1.0,
            0.1,
            [1.0, 0.0],
            [[0.1, 0.0], [0.0, 0.1]],
        );

        let candidate_snapshot1 = create_snapshot(
            2,
            1.2,
            0.2,
            [1.2, 0.0],
            [[0.2, 0.0], [0.0, 0.2]],
        );

        let candidate_snapshot2 = create_snapshot(
            3,
            1.4,
            0.3,
            [1.4, 0.0],
            [[0.3, 0.0], [0.0, 0.3]],
        );

        let combined = combine_with_pps(pps_snapshot, vec![candidate_snapshot1, candidate_snapshot2]);
        assert_eq!(combined.len(), 4);
    }

    // Tests the combination of PPS when there are no candidates
    #[test]
    fn test_combine_with_pps_no_candidates() {
        let pps_snapshot = create_snapshot(
            1,
            1.0,
            0.1,
            [1.0, 0.0],
            [[0.1, 0.0], [0.0, 0.1]],
        );

        let combined = combine_with_pps(pps_snapshot, vec![]);
        assert!(combined.is_empty());
    }

    // Tests the combine_sources function when the inouts have the same offsets and uncertainties, 0
    #[test]
    fn test_combine_sources_zeros() {
        let pps_snapshot = create_snapshot(
            1,
            0.0,
            0.0,
            [0.0, 0.0],
            [[0.0, 0.0], [0.0, 0.0]],
        );

        let other_snapshot = create_snapshot(
            2,
            0.0,
            0.0,
            [0.0, 0.0],
            [[0.0, 0.0], [0.0, 0.0]],
        );

        let combined_snapshot = combine_sources(pps_snapshot, other_snapshot);

        assert_eq!(combined_snapshot.state.ventry(0), 0.0);
        assert_eq!(combined_snapshot.uncertainty.entry(0, 0), 0.0);
    }

    // Tests the combine_sources function when the inputs have the same offsets and no uncertainty
    #[test]
    fn test_combine_sources_zero_uncertainty() {
        let pps_snapshot = create_snapshot(
            1,
            1.0,
            0.0,
            [1.0, 0.0],
            [[0.0, 0.0], [0.0, 0.0]],
        );

        let other_snapshot = create_snapshot(
            2,
            1.0,
            0.0,
            [1.0, 0.0],
            [[0.0, 0.0], [0.0, 0.0]],
        );

        let combined_snapshot = combine_sources(pps_snapshot, other_snapshot);

        assert!((combined_snapshot.state.ventry(0) - 2.0).abs() < 1e-6);
        assert!(combined_snapshot.uncertainty.entry(0, 0) == 0.0);
    }

    // Tests the combine_sources function when the inputs have the different offsets and same large uncertainty
    #[test]
    fn test_combine_sources_large_uncertainty() {
        let pps_snapshot = create_snapshot(
            1,
            1.0,
            50.0,
            [1.0, 0.0],
            [[50.0, 0.0], [0.0, 50.0]],
        );

        let other_snapshot = create_snapshot(
            2,
            2.0,
            50.0,
            [2.0, 0.0],
            [[50.0, 0.0], [0.0, 50.0]],
        );

        let combined_snapshot = combine_sources(pps_snapshot, other_snapshot);

        assert!(combined_snapshot.state.ventry(0) >= 1.0 && combined_snapshot.state.ventry(0) <= 2.0);
        assert!(combined_snapshot.uncertainty.entry(0, 0) <= 50.0);
    }
}
