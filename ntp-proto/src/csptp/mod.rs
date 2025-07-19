use std::io::Cursor;

use statime::datastructures::WireFormat;

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
            statime::datastructures::messages::MessageBody::Sync(sync_message) => Some(sync_message.origin_timestamp),
            _ => None
        }
    }

    pub fn get_correction(&self) -> statime::datastructures::common::TimeInterval {
        self.inner.header.correction_field
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
