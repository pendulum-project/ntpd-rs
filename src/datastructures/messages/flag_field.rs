use crate::datastructures::{WireFormat, WireFormatError};

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
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
    fn wire_size(&self) -> usize {
        2
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), WireFormatError> {
        buffer[0] = 0;
        buffer[1] = 0;

        buffer[0] |= self.alternate_master_flag as u8;
        buffer[0] |= (self.two_step_flag as u8) << 1;
        buffer[0] |= (self.unicast_flag as u8) << 2;
        buffer[0] |= (self.ptp_profile_specific_1 as u8) << 5;
        buffer[0] |= (self.ptp_profile_specific_2 as u8) << 6;
        buffer[1] |= self.leap61 as u8;
        buffer[1] |= (self.leap59 as u8) << 1;
        buffer[1] |= (self.current_utc_offset_valid as u8) << 2;
        buffer[1] |= (self.ptp_timescale as u8) << 3;
        buffer[1] |= (self.time_tracable as u8) << 4;
        buffer[1] |= (self.frequency_tracable as u8) << 5;
        buffer[1] |= (self.synchronization_uncertain as u8) << 6;

        Ok(())
    }

    fn deserialize(buffer: &[u8]) -> Result<Self, WireFormatError> {
        Ok(Self {
            alternate_master_flag: (buffer[0] & (1 << 0)) > 0,
            two_step_flag: (buffer[0] & (1 << 1)) > 0,
            unicast_flag: (buffer[0] & (1 << 2)) > 0,
            ptp_profile_specific_1: (buffer[0] & (1 << 5)) > 0,
            ptp_profile_specific_2: (buffer[0] & (1 << 6)) > 0,
            leap61: (buffer[1] & (1 << 0)) > 0,
            leap59: (buffer[1] & (1 << 1)) > 0,
            current_utc_offset_valid: (buffer[1] & (1 << 2)) > 0,
            ptp_timescale: (buffer[1] & (1 << 3)) > 0,
            time_tracable: (buffer[1] & (1 << 4)) > 0,
            frequency_tracable: (buffer[1] & (1 << 5)) > 0,
            synchronization_uncertain: (buffer[1] & (1 << 6)) > 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        for (i, (byte_representation, flag_representation)) in
            representations.into_iter().enumerate()
        {
            // Test the serialization output
            let mut serialization_buffer = [0; 2];
            flag_representation
                .serialize(&mut serialization_buffer)
                .unwrap();
            assert_eq!(
                serialization_buffer, byte_representation,
                "The serialized flag field is not what it's supposed to for variant {}",
                i
            );

            // Test the deserialization output
            let deserialized_flag_field = FlagField::deserialize(&byte_representation).unwrap();
            assert_eq!(
                deserialized_flag_field, flag_representation,
                "The deserialized flag field is not what it's supposed to for variant {}",
                i
            );
        }
    }
}
