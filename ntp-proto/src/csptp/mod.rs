use std::io::Cursor;

use statime::datastructures::{common::TlvSetBuilder, WireFormat};

const CSPTP_REQUEST_TLV: u16 = 0xFF00;
const CSPTP_RESPONSE_TLV: u16 = 0xFF01;

pub struct CsptpPacket<'a> {
    inner: statime::datastructures::messages::Message<'a>,
}

impl<'a> CsptpPacket<'a> {
    fn deserialize(data: &'a [u8]) -> Result<Self, statime::datastructures::WireFormatError> {
        Ok(CsptpPacket {
            inner: statime::datastructures::messages::Message::deserialize(data)?,
        })
    }

    fn serialize(
        &self,
        w: &mut Cursor<&mut [u8]>,
    ) -> Result<(), statime::datastructures::WireFormatError> {
        let start = w.position() as usize;
        let bytes = self.inner.serialize(&mut w.get_mut()[start..])?;
        w.set_position((start + bytes) as u64);
        Ok(())
    }

    pub fn get_csptp_request_flags(&self) -> Option<CsptpRequestFlags> {
        for tlv in self.inner.suffix.tlv() {
            if tlv.tlv_type.to_primitive() == CSPTP_REQUEST_TLV {
                let flags = tlv.value.get(0).copied().unwrap_or_default();
                return Some(CsptpRequestFlags {
                    csptp_status: flags & 1 != 0,
                    alt_timescale: flags & 2 != 0,
                });
            }
        }

        None
    }

    pub fn get_csptp_response_data(&self) -> Option<CsptpResponseData> {
        for tlv in self.inner.suffix.tlv() {
            if tlv.tlv_type.to_primitive() == CSPTP_RESPONSE_TLV && tlv.value.len() >= 18 {
                return Some(CsptpResponseData {
                    req_ingress_timestamp:
                        statime::datastructures::common::WireTimestamp::deserialize(
                            &tlv.value[0..10],
                        )
                        .unwrap(),
                    req_ingress_correction:
                        statime::datastructures::common::TimeInterval::deserialize(
                            &tlv.value[10..18],
                        )
                        .unwrap(),
                });
            }
        }

        None
    }

    pub fn get_origin_timestamp(&self) -> Option<statime::datastructures::common::WireTimestamp> {
        match self.inner.body {
            statime::datastructures::messages::MessageBody::Sync(sync_message) => {
                Some(sync_message.origin_timestamp)
            }
            _ => None,
        }
    }

    pub fn get_correction(&self) -> statime::datastructures::common::TimeInterval {
        self.inner.header.correction_field
    }

    pub fn request(buffer: &'a mut [u8], sequence_id: u16) -> Self {
        let flags = [0u8; 4];
        let request_tlv = statime::datastructures::common::Tlv {
            tlv_type: statime::datastructures::common::TlvType::Reserved(CSPTP_REQUEST_TLV),
            value: flags.as_slice().into(),
        };
        let mut tlvs = statime::datastructures::common::TlvSetBuilder::new(buffer);
        tlvs.add(request_tlv).unwrap();
        Self {
            inner: statime::datastructures::messages::Message {
                header: statime::datastructures::messages::Header {
                    sdo_id: statime::config::SdoId::try_from(0x300).unwrap(),
                    version: statime::datastructures::messages::PtpVersion::new(2, 0).unwrap(),
                    domain_number: 0,
                    alternate_master_flag: false,
                    two_step_flag: false,
                    unicast_flag: true,
                    ptp_profile_specific_1: false,
                    ptp_profile_specific_2: false,
                    leap61: false,
                    leap59: false,
                    current_utc_offset_valid: false,
                    ptp_timescale: true,
                    time_tracable: false,
                    frequency_tracable: false,
                    synchronization_uncertain: false,
                    correction_field: Default::default(),
                    source_port_identity: Default::default(),
                    sequence_id,
                    log_message_interval: 0x7f,
                },
                body: statime::datastructures::messages::MessageBody::Sync(
                    statime::datastructures::messages::sync::SyncMessage {
                        origin_timestamp: Default::default(),
                    },
                ),
                suffix: tlvs.build(),
            },
        }
    }

    pub fn timestamp_response(
        buffer: &'a mut [u8],
        request: CsptpPacket<'_>,
        receive_timestamp: statime::datastructures::common::WireTimestamp,
        send_timestamp: statime::datastructures::common::WireTimestamp,
    ) -> Self {
        let mut tlvs = TlvSetBuilder::new(buffer);
        let mut innerbuf = [0u8;18];
        receive_timestamp.serialize(&mut innerbuf[0..10]).unwrap();
        request.get_correction().serialize(&mut innerbuf[10..18]).unwrap();
        tlvs.add(statime::datastructures::common::Tlv {
            tlv_type: statime::datastructures::common::TlvType::Reserved(CSPTP_RESPONSE_TLV),
            value: innerbuf.as_slice().into(),
        }).unwrap();
        Self {
            inner: statime::datastructures::messages::Message {
                header: statime::datastructures::messages::Header {
                    sdo_id: statime::config::SdoId::try_from(0x300).unwrap(),
                    version: statime::datastructures::messages::PtpVersion::new(2, 0).unwrap(),
                    domain_number: 0,
                    alternate_master_flag: false,
                    two_step_flag: false,
                    unicast_flag: true,
                    ptp_profile_specific_1: false,
                    ptp_profile_specific_2: false,
                    leap61: false,
                    leap59: false,
                    current_utc_offset_valid: false,
                    ptp_timescale: true,
                    time_tracable: false,
                    frequency_tracable: false,
                    synchronization_uncertain: false,
                    correction_field: Default::default(),
                    source_port_identity: Default::default(),
                    sequence_id: request.inner.header.sequence_id,
                    log_message_interval: 0x7f,
                },
                body: statime::datastructures::messages::MessageBody::Sync(
                    statime::datastructures::messages::sync::SyncMessage {
                        origin_timestamp: send_timestamp,
                    },
                ),
                suffix: tlvs.build(),
            },
        }
    }
}

pub struct CsptpRequestFlags {
    pub csptp_status: bool,
    pub alt_timescale: bool,
}

pub struct CsptpResponseData {
    pub req_ingress_timestamp: statime::datastructures::common::WireTimestamp,
    pub req_ingress_correction: statime::datastructures::common::TimeInterval,
}
