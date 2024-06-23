use super::{matrix::{Matrix, Vector}, SourceSnapshot};

pub(crate) fn combine_with_pps<Index: Copy + PartialEq + std::fmt::Debug>(
    pps: SourceSnapshot<Index>,
    candidates: Vec<SourceSnapshot<Index>>,
) -> Vec<SourceSnapshot<Index>> {
    println!("COMBINE WITH PPS: Number of candidates: {}", candidates.len());
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
    // assign the offset of pps after each measurement
    let pps_offset = pps_snapshot.offset();
    // assign the frequency error of pps after each measurement
    let pps_offset_uncertainty = pps_snapshot.offset_uncertainty();
    // assign the offset of other sources after each measurement
    let other_offset = other_snapshot.offset();
    // assign the frequency error of other sources after each measurement
    let other_offset_uncertainty = other_snapshot.offset_uncertainty();

    // find the smaller whole second the other source is in range of ie if offset 12.3 this assigns 12.0
    let full_second_floor = other_offset.floor();
    // find the larger whole second the other source is in range of ie if offset 12.3 this assigns 13.0
    let full_second_ceil = other_offset.ceil();

    // create 4 endpoints for both the larger and smaller whole seconds the offset of current measurement is in range of
    // use the pps offset by adding and subtracting from the whole seconds to find the endpoints of the combined source
    // these endpoints will then be used to compare with the uncombined source range to fins the closest endpoint
    let pps_floor_positive = full_second_floor + pps_offset;
    let pps_floor_negative = full_second_floor - pps_offset;
    let pps_ceil_positive = full_second_ceil + pps_offset;
    let pps_ceil_negative = full_second_ceil - pps_offset;

    // calculate the uncombined endpoints of the source
    let other_minimum = other_offset - other_offset_uncertainty;
    let other_maximum = other_offset + other_offset_uncertainty;

    // calculate the difference of each combined endpoint from the uncombined endpoint
    let floor_positive_diff = (pps_floor_positive - other_minimum).abs();
    let floor_negative_diff = (pps_floor_negative - other_minimum).abs();
    let ceil_positive_diff = (pps_ceil_positive - other_maximum).abs();
    let ceil_negative_diff = (pps_ceil_negative - other_maximum).abs();

    // assign the minimum difference
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

    // assign the new offset for the combined source
    let combined_state = Vector::<2>::new([
        [new_offset],
        [other_snapshot.get_state_vector().ventry(1)],
    ]);

    // uncombined source frequency error stays the same
    let other_uncertainty_matrix = other_snapshot.get_uncertainty_matrix();

    // assign the frequency error of pps to the combined source
    let combined_uncertainty = Matrix::<2, 2>::new([
        [pps_offset_uncertainty, other_uncertainty_matrix.entry(0, 1)],
        [other_uncertainty_matrix.entry(1, 0), other_uncertainty_matrix.entry(1, 1)],
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
    use crate::algorithm::kalman::SourceSnapshot;
    use crate::algorithm::kalman::matrix::{Matrix, Vector};
    use crate::time_types::NtpTimestamp;

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
            source_uncertainty: 0.0,
            source_delay: 0.0,
            leap_indicator: Default::default(),
            last_update: NtpTimestamp::from_fixed_int(0),
        }
    }

    // TESTS TO COME HERE
}
