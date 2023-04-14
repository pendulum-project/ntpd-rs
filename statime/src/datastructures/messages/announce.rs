use crate::datastructures::datasets::TimePropertiesDS;
use crate::datastructures::{
    common::{ClockIdentity, ClockQuality, TimeSource, Timestamp},
    WireFormat,
};
use getset::CopyGetters;

use super::Header;

#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct AnnounceMessage {
    pub(crate) header: Header,
    pub(crate) origin_timestamp: Timestamp,
    pub(crate) current_utc_offset: i16,
    pub(crate) grandmaster_priority_1: u8,
    pub(crate) grandmaster_clock_quality: ClockQuality,
    pub(crate) grandmaster_priority_2: u8,
    pub(crate) grandmaster_identity: ClockIdentity,
    pub(crate) steps_removed: u16,
    pub(crate) time_source: TimeSource,
}

impl AnnounceMessage {
    pub fn content_size(&self) -> usize {
        30
    }

    pub fn serialize_content(
        &self,
        buffer: &mut [u8],
    ) -> Result<(), crate::datastructures::WireFormatError> {
        self.origin_timestamp.serialize(&mut buffer[0..10])?;
        buffer[10..12].copy_from_slice(&self.current_utc_offset.to_be_bytes());
        buffer[13] = self.grandmaster_priority_1;
        self.grandmaster_clock_quality
            .serialize(&mut buffer[14..18])?;
        buffer[18] = self.grandmaster_priority_2;
        self.grandmaster_identity.serialize(&mut buffer[19..27])?;
        buffer[27..29].copy_from_slice(&self.steps_removed.to_be_bytes());
        buffer[29] = self.time_source.to_primitive();

        Ok(())
    }

    pub fn deserialize_content(
        header: Header,
        buffer: &[u8],
    ) -> Result<Self, crate::datastructures::WireFormatError> {
        Ok(Self {
            header,
            origin_timestamp: Timestamp::deserialize(&buffer[0..10])?,
            current_utc_offset: i16::from_be_bytes(buffer[10..12].try_into().unwrap()),
            grandmaster_priority_1: buffer[13],
            grandmaster_clock_quality: ClockQuality::deserialize(&buffer[14..18])?,
            grandmaster_priority_2: buffer[18],
            grandmaster_identity: ClockIdentity::deserialize(&buffer[19..27])?,
            steps_removed: u16::from_be_bytes(buffer[27..29].try_into().unwrap()),
            time_source: TimeSource::from_primitive(buffer[29]),
        })
    }

    pub fn time_properties(&self) -> TimePropertiesDS {
        TimePropertiesDS {
            current_utc_offset: self.current_utc_offset,
            current_utc_offset_valid: self.header.current_utc_offset_valid,
            leap59: self.header.leap61,
            leap61: self.header.leap59,
            time_traceable: self.header.time_tracable,
            frequency_traceable: self.header.frequency_tracable,
            ptp_timescale: self.header.ptp_timescale,
            time_source: self.time_source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastructures::common::ClockAccuracy;

    #[test]
    fn announce_wireformat() {
        let representations = [(
            [
                0x00, 0x00, 0x45, 0xb1, 0x11, 0x5a, 0x0a, 0x73, 0x46, 0x60, 0x00, 0x00, 0x00, 0x60,
                0x00, 0x00, 0x00, 0x80, 0x63, 0xff, 0xff, 0x00, 0x09, 0xba, 0xf8, 0x21, 0x00, 0x00,
                0x80, 0x80,
            ],
            AnnounceMessage {
                header: Header::default(),
                origin_timestamp: Timestamp {
                    seconds: 1169232218,
                    nanos: 175326816,
                },
                current_utc_offset: 0,
                grandmaster_priority_1: 96,
                grandmaster_clock_quality: ClockQuality {
                    clock_class: 0,
                    clock_accuracy: ClockAccuracy::Reserved,
                    offset_scaled_log_variance: 128,
                },
                grandmaster_priority_2: 99,
                grandmaster_identity: ClockIdentity([
                    0xff, 0xff, 0x00, 0x09, 0xba, 0xf8, 0x21, 0x00,
                ]),
                steps_removed: 128,
                time_source: TimeSource::Unknown(0x80),
            },
        )];

        for (byte_representation, object_representation) in representations {
            // Test the serialization output
            let mut serialization_buffer = [0; 30];
            object_representation
                .serialize_content(&mut serialization_buffer)
                .unwrap();
            assert_eq!(serialization_buffer, byte_representation);

            // Test the deserialization output
            let deserialized_data =
                AnnounceMessage::deserialize_content(Header::default(), &byte_representation)
                    .unwrap();
            assert_eq!(deserialized_data, object_representation);
        }
    }
}
