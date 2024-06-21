
use super::{matrix::{Matrix, Vector}, SourceSnapshot};


pub(crate) fn combine_with_pps<Index: Copy>(candidates: Vec<SourceSnapshot<Index>>, pps_source_id: i32) -> Vec<SourceSnapshot<Index>> {
    println!("COMBINE WITH PPS: Number of candidates: {}", candidates.len());
    for snapshot in candidates.iter() {
        println!("COMBINE PPS uncertainty: {:?}, offset: {:?}", snapshot.offset_uncertainty(), snapshot.offset());
    }

    
    // Convert PPS source ID to zero-based index
    let pps_index = pps_source_id - 1;

    let mut results = Vec::new();
    let mut pps_snapshot = None;

    for (i, snapshot) in candidates.into_iter().enumerate() {
        if i == pps_index as usize {
            pps_snapshot = Some(snapshot);
        } else {
            results.push(snapshot.clone());
        }
    }

    if let Some(pps) = pps_snapshot {
        let mut final_candidates = Vec::new();
        for snapshot in results.clone() {
            let combined = combine_sources(pps.clone(), snapshot.clone());
            final_candidates.push(snapshot);
            final_candidates.push(combined);
        }
        final_candidates
    } else {
        results
    }
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

    let pps_floor = full_second_floor + pps_offset;
    let pps_ceil = full_second_ceil + pps_offset;

    let other_minimum = other_offset - other_offset_uncertainty;
    let other_maximum = other_offset + other_offset_uncertainty;

    let pps_floor_difference = (other_minimum - pps_floor).abs();
    let pps_ceil_difference = (other_maximum - pps_ceil).abs();

    let combined_uncertainty: Matrix<2, 2>;

    if pps_floor_difference < pps_ceil_difference {

        combined_uncertainty = Matrix::<2, 2>::new([
            [(pps_offset_uncertainty + other_offset_uncertainty) / 2.0, 0.0],
            [0.0, (pps_snapshot.uncertainty.entry(1, 1) + other_snapshot.uncertainty.entry(1, 1)) / 2.0],
        ]);
    } else {
        combined_uncertainty = Matrix::<2, 2>::new([
            [(pps_offset_uncertainty + other_offset_uncertainty) / 2.0, 0.0],
            [0.0, (pps_snapshot.uncertainty.entry(1, 1) + other_snapshot.uncertainty.entry(1, 1)) / 2.0],
        ]);
    }

    SourceSnapshot {
        index: other_snapshot.index, 
        state: other_snapshot.state,
        uncertainty: combined_uncertainty,
        delay: other_snapshot.delay,
        source_uncertainty: other_snapshot.source_uncertainty,
        source_delay: other_snapshot.source_delay,
        leap_indicator: other_snapshot.leap_indicator,
        last_update: other_snapshot.last_update,
    }
}