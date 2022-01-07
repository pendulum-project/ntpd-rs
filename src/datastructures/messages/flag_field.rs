use crate::datastructures::WireFormat;
use bitvec::order::Lsb0;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagField {
    pub alternate_master_flag: bool,
    pub two_step_flag: bool,
    pub unicast_flag: bool,
    pub ptp_profile_specific_1: bool,
    pub ptp_profile_specific_2: bool,
    pub leap61: bool,
    pub leap59: bool,
    pub current_utc_offset_valid: bool,
    pub ptp_timescale: bool,
    pub time_tracable: bool,
    pub frequency_tracable: bool,
    pub synchronization_uncertain: bool,
}

impl WireFormat for FlagField {
    const BITSIZE: usize = 16;

    fn serialize<T>(&self, buffer: &mut bitvec::slice::BitSlice<Lsb0, T>)
    where
        T: bitvec::store::BitStore,
    {
        buffer.set(0, self.alternate_master_flag);
        buffer.set(1, self.two_step_flag);
        buffer.set(2, self.unicast_flag);
        buffer.set(5, self.ptp_profile_specific_1);
        buffer.set(6, self.ptp_profile_specific_2);
        buffer.set(8, self.leap61);
        buffer.set(9, self.leap59);
        buffer.set(10, self.current_utc_offset_valid);
        buffer.set(11, self.ptp_timescale);
        buffer.set(12, self.time_tracable);
        buffer.set(13, self.frequency_tracable);
        buffer.set(14, self.synchronization_uncertain);
    }

    fn deserialize<T>(buffer: &bitvec::slice::BitSlice<Lsb0, T>) -> Self
    where
        T: bitvec::store::BitStore,
    {
        Self {
            alternate_master_flag: buffer[0],
            two_step_flag: buffer[1],
            unicast_flag: buffer[2],
            ptp_profile_specific_1: buffer[5],
            ptp_profile_specific_2: buffer[6],
            leap61: buffer[8],
            leap59: buffer[9],
            current_utc_offset_valid: buffer[10],
            ptp_timescale: buffer[11],
            time_tracable: buffer[12],
            frequency_tracable: buffer[13],
            synchronization_uncertain: buffer[14],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::{bitarr, order::Lsb0, store::BitStore, view::BitView};

    #[test]
    fn flagfield_wireformat() {
        #[rustfmt::skip]
        let representations = [
            ([0x00, 0x00u8], FlagField::default()),
            ([0x01, 0x00u8], FlagField { alternate_master_flag: true, ..Default::default() }),
            ([0x02, 0x00u8], FlagField { two_step_flag: true, ..Default::default() }),
            ([0x04, 0x00u8], FlagField { unicast_flag: true, ..Default::default() }),
            ([0x20, 0x00u8], FlagField { ptp_profile_specific_1: true, ..Default::default() }),
            ([0x40, 0x00u8], FlagField { ptp_profile_specific_2: true, ..Default::default() }),
            ([0x00, 0x01u8], FlagField { leap61: true, ..Default::default() }),
            ([0x00, 0x02u8], FlagField { leap59: true, ..Default::default() }),
            ([0x00, 0x04u8], FlagField { current_utc_offset_valid: true, ..Default::default() }),
            ([0x00, 0x08u8], FlagField { ptp_timescale: true, ..Default::default() }),
            ([0x00, 0x10u8], FlagField { time_tracable: true, ..Default::default() }),
            ([0x00, 0x20u8], FlagField { frequency_tracable: true, ..Default::default() }),
            ([0x00, 0x40u8], FlagField { synchronization_uncertain: true, ..Default::default() }),
        ];

        for (i, (bit_representation, flag_representation)) in representations.iter().enumerate() {
            // Test the serialization output
            let mut serialization_buffer = bitarr![const Lsb0, u8; 0; FlagField::BITSIZE];
            flag_representation.serialize(&mut serialization_buffer);
            assert_eq!(
                serialization_buffer,
                bit_representation.view_bits::<Lsb0>(),
                "The serialized flag field is not what it's supposed to for variant {}",
                i
            );

            // Test the deserialization output
            let deserialized_flag_field =
                FlagField::deserialize(bit_representation.view_bits::<Lsb0>());
            assert_eq!(
                &deserialized_flag_field, flag_representation,
                "The deserialized flag field is not what it's supposed to for variant {}",
                i
            );
        }
    }
}
