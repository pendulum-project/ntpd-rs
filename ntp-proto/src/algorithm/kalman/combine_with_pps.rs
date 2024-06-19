use crate::config::SynchronizationConfig;

use super::{config::AlgorithmConfig, SourceSnapshot};


pub(crate) fn combine_with_pps<Index: Copy>(candidates: Vec<SourceSnapshot<Index>>) -> Vec<SourceSnapshot<Index>> {

    // for snapshot in &candidates {
    //     println!("COMBINE WITH PPS");
    //     println!("{:?}", snapshot);
    // }
    for snapshot in candidates.iter() {
        println!("COMBINE PPS uncetainty: {:?}, offsetL {:?}", snapshot.offset_uncertainty(), snapshot.offset());
    }


    let pps_snapshot = candidates.iter().find(|snapshot| {
        // Replace this condition with the actual condition to identify the PPS snapshot
        // For example:
        // snapshot.is_pps()
        true // Placeholder condition
    });

    // If found, return it in a new vector, otherwise return an empty vector
    match pps_snapshot {
        Some(snapshot) => vec![snapshot.clone()],
        None => vec![],
    }
}

// fn combine_sources<Index: Copy>(
//     pps_snapshot: SourceSnapshot<Index>,
//     other_snapshot: SourceSnapshot<Index>,
// ) -> SourceSnapshot<Index> {
//     let pps_offset = pps_snapshot.offset();
//     let pps_offset_uncertainty = pps_snapshot.offset_uncertainty();
//     let other_offset = other_snapshot.offset();
//     let other_offset_uncertainty = other_snapshot.offset_uncertainty();

//     let full_second_floor = other_offset.floor();
//     let full_second_ceil = other_offset.ceil();

//     let pps_floor = full_second_floor + pps_offset;
//     let pps_ceil = full_second_ceil + pps_offset;

//     let other_minimum = other_offset - other_offset_uncertainty;
//     let other_maximum = other_offset + other_offset_uncertainty;

//     let pps_floor_difference = (other_minimum - pps_floor).abs();
//     let pps_ceil_difference = (other_maximum - pps_ceil).abs();

//     let combined_state: Vector<2>;
//     let combined_uncertainty: Matrix<2, 2>;

//     if pps_floor_difference < pps_ceil_difference {
//         combined_state = Vector::<2>::new([
//             [(other_snapshot.state.ventry(0) + pps_snapshot.state.ventry(0)) / 2.0],
//             [(other_snapshot.state.ventry(1) + pps_snapshot.state.ventry(1)) / 2.0],
//         ]);

//         combined_uncertainty = Matrix::<2, 2>::new([
//             [(pps_offset_uncertainty + other_offset_uncertainty) / 2.0, 0.0],
//             [0.0, (pps_snapshot.uncertainty.entry(1, 1) + other_snapshot.uncertainty.entry(1, 1)) / 2.0],
//         ]);
//     } else {
//         combined_state = Vector::<2>::new([
//             [(other_snapshot.state.ventry(0) + pps_snapshot.state.ventry(0)) / 2.0],
//             [(other_snapshot.state.ventry(1) + pps_snapshot.state.ventry(1)) / 2.0],
//         ]);

//         combined_uncertainty = Matrix::<2, 2>::new([
//             [(pps_offset_uncertainty + other_offset_uncertainty) / 2.0, 0.0],
//             [0.0, (pps_snapshot.uncertainty.entry(1, 1) + other_snapshot.uncertainty.entry(1, 1)) / 2.0],
//         ]);
//     }

//     SourceSnapshot {
//         index: other_snapshot.index, 
//         state: combined_state,
//         uncertainty: combined_uncertainty,
//         delay: (other_snapshot.delay + pps_snapshot.delay) / 2.0,
//         source_uncertainty: NtpDuration::from_seconds(
//             (other_snapshot.source_uncertainty.to_seconds() + pps_snapshot.source_uncertainty.to_seconds()) / 2.0,
//         ),
//         source_delay: NtpDuration::from_seconds(
//             (other_snapshot.source_delay.to_seconds() + pps_snapshot.source_delay.to_seconds()) / 2.0,
//         ),
//         leap_indicator: if pps_snapshot.leap_indicator == other_snapshot.leap_indicator {
//             pps_snapshot.leap_indicator
//         } else {
//             NtpLeapIndicator::Unknown
//         },
//         last_update: std::cmp::max(pps_snapshot.last_update, other_snapshot.last_update),
//     }
// }