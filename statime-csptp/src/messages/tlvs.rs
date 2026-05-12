use statime_wire::{
    ClockIdentity, ClockQuality, TimeInterval, Timestamp, Tlv, TlvSetBuilder, TlvType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CsptpRequestTlv {
    pub(crate) csptp_status: bool,
    pub(crate) alt_timescale: bool,
}

impl CsptpRequestTlv {
    pub(crate) fn try_from(tlv: &Tlv<'_>) -> Option<Self> {
        (tlv.tlv_type == TlvType::CsptpRequest)
            .then(|| {
                tlv.value.first().map(|flags| CsptpRequestTlv {
                    csptp_status: (flags & 1) != 0,
                    alt_timescale: (flags & 2) != 0,
                })
            })
            .flatten()
    }

    pub(crate) fn add_to(self, builder: &mut TlvSetBuilder<'_>) -> Result<(), statime_wire::Error> {
        let mut content = [0u8; 4];
        if self.csptp_status {
            content[0] |= 1;
        }
        if self.alt_timescale {
            content[0] |= 2;
        }
        builder.add(&Tlv {
            tlv_type: TlvType::CsptpRequest,
            value: content.as_slice().into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CsptpResponseTlv {
    pub(crate) req_ingress_timestamp: Timestamp,
    pub(crate) req_correction_field: TimeInterval,
}

impl CsptpResponseTlv {
    pub(crate) fn try_from(tlv: &Tlv<'_>) -> Option<Self> {
        (tlv.tlv_type == TlvType::CsptpResponse)
            .then(|| {
                tlv.value.get(0..18).and_then(|content| {
                    Some(CsptpResponseTlv {
                        req_ingress_timestamp: Timestamp::deserialize(&content[0..10]).ok()?,
                        req_correction_field: TimeInterval::deserialize(&content[10..18]).ok()?,
                    })
                })
            })
            .flatten()
    }

    pub(crate) fn add_to(self, builder: &mut TlvSetBuilder<'_>) -> Result<(), statime_wire::Error> {
        let mut content = [0u8; 18];
        self.req_ingress_timestamp.serialize(&mut content[0..10])?;
        self.req_correction_field.serialize(&mut content[10..18])?;
        builder.add(&Tlv {
            tlv_type: TlvType::CsptpResponse,
            value: content.as_slice().into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CsptpStatusTlv {
    pub(crate) grandmaster_priority1: u8,
    pub(crate) grandmaster_clock_quality: ClockQuality,
    pub(crate) grandmaster_priority2: u8,
    pub(crate) steps_removed: u16,
    pub(crate) current_utc_offset: i16,
    pub(crate) grandmaster_identity: ClockIdentity,
}

impl CsptpStatusTlv {
    pub(crate) fn try_from(tlv: &Tlv<'_>) -> Option<Self> {
        (tlv.tlv_type == TlvType::CsptpStatus)
            .then(|| {
                tlv.value.get(0..18).and_then(|content| {
                    Some(CsptpStatusTlv {
                        grandmaster_priority1: content[0],
                        grandmaster_clock_quality: ClockQuality::deserialize(&content[1..5])
                            .ok()?,
                        grandmaster_priority2: content[5],
                        steps_removed: u16::from_be_bytes(content[6..8].try_into().unwrap()),
                        current_utc_offset: i16::from_be_bytes(content[8..10].try_into().unwrap()),
                        grandmaster_identity: ClockIdentity::deserialize(&content[10..18]).ok()?,
                    })
                })
            })
            .flatten()
    }

    pub(crate) fn add_to(self, builder: &mut TlvSetBuilder<'_>) -> Result<(), statime_wire::Error> {
        let mut content = [0u8; 18];
        content[0] = self.grandmaster_priority1;
        self.grandmaster_clock_quality
            .serialize(&mut content[1..5])?;
        content[5] = self.grandmaster_priority2;
        content[6..8].copy_from_slice(&self.steps_removed.to_be_bytes());
        content[8..10].copy_from_slice(&self.current_utc_offset.to_be_bytes());
        self.grandmaster_identity.serialize(&mut content[10..18])?;
        builder.add(&Tlv {
            tlv_type: TlvType::CsptpStatus,
            value: content.as_slice().into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use statime_wire::{
        ClockAccuracy, ClockIdentity, ClockQuality, TimeInterval, Timestamp, Tlv, TlvSetBuilder,
        TlvType,
    };

    use super::{CsptpRequestTlv, CsptpResponseTlv, CsptpStatusTlv};

    #[test]
    fn csptp_request_tlv() {
        let content = [0, 0, 0, 0];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpRequest,
            value: content.as_slice().into(),
        };
        let parsed = CsptpRequestTlv::try_from(&tlv).unwrap();
        assert!(!parsed.csptp_status);
        assert!(!parsed.alt_timescale);

        let content = [1, 0, 0, 0];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpRequest,
            value: content.as_slice().into(),
        };
        let parsed = CsptpRequestTlv::try_from(&tlv).unwrap();
        assert!(parsed.csptp_status);
        assert!(!parsed.alt_timescale);

        let content = [2, 0, 0, 0];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpRequest,
            value: content.as_slice().into(),
        };
        let parsed = CsptpRequestTlv::try_from(&tlv).unwrap();
        assert!(!parsed.csptp_status);
        assert!(parsed.alt_timescale);

        let content = [3, 0, 0, 0];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpRequest,
            value: content.as_slice().into(),
        };
        let parsed = CsptpRequestTlv::try_from(&tlv).unwrap();
        assert!(parsed.csptp_status);
        assert!(parsed.alt_timescale);

        let mut buffer = [0u8; 8];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpRequestTlv {
            csptp_status: false,
            alt_timescale: false,
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpRequest);
        assert_eq!(tlv.value, [0, 0, 0, 0].as_slice());

        let mut buffer = [0u8; 8];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpRequestTlv {
            csptp_status: true,
            alt_timescale: false,
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpRequest);
        assert_eq!(tlv.value, [1, 0, 0, 0].as_slice());

        let mut buffer = [0u8; 8];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpRequestTlv {
            csptp_status: false,
            alt_timescale: true,
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpRequest);
        assert_eq!(tlv.value, [2, 0, 0, 0].as_slice());

        let mut buffer = [0u8; 8];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpRequestTlv {
            csptp_status: true,
            alt_timescale: true,
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpRequest);
        assert_eq!(tlv.value, [3, 0, 0, 0].as_slice());
    }

    #[test]
    fn csptp_response_tlv() {
        let content = [0, 0, 0, 0, 0, 100, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 25];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpResponse,
            value: content.as_slice().into(),
        };
        let parsed = CsptpResponseTlv::try_from(&tlv).unwrap();
        assert_eq!(parsed.req_ingress_timestamp.seconds(), 100);
        assert_eq!(parsed.req_ingress_timestamp.nanos(), 50);
        assert_eq!(parsed.req_correction_field.0, 25);

        let mut buffer = [0u8; 22];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpResponseTlv {
            req_ingress_timestamp: Timestamp::new(200, 100).unwrap(),
            req_correction_field: TimeInterval(50),
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpResponse);
        assert_eq!(
            tlv.value,
            [0, 0, 0, 0, 0, 200, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 50].as_slice()
        );
    }

    #[test]
    fn csptp_status_tlv() {
        let content = [
            127, 248, 0x27, 0x37, 0x80, 230, 0, 15, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let tlv = Tlv {
            tlv_type: TlvType::CsptpStatus,
            value: content.as_slice().into(),
        };
        let parsed = CsptpStatusTlv::try_from(&tlv).unwrap();
        assert_eq!(parsed.grandmaster_priority1, 127);
        assert_eq!(parsed.grandmaster_clock_quality.clock_class, 248);
        assert_eq!(
            parsed.grandmaster_clock_quality.clock_accuracy,
            ClockAccuracy::US100
        );
        assert_eq!(
            parsed.grandmaster_clock_quality.offset_scaled_log_variance,
            0x3780
        );
        assert_eq!(parsed.grandmaster_priority2, 230);
        assert_eq!(parsed.steps_removed, 15);
        assert_eq!(parsed.current_utc_offset, 0);
        assert_eq!(
            parsed.grandmaster_identity,
            ClockIdentity([1, 2, 3, 4, 5, 6, 7, 8])
        );

        let mut buffer = [0; 22];
        let mut builder = TlvSetBuilder::new(&mut buffer);
        CsptpStatusTlv {
            grandmaster_priority1: 15,
            grandmaster_clock_quality: ClockQuality {
                clock_class: 248,
                clock_accuracy: ClockAccuracy::MS1,
                offset_scaled_log_variance: 0x8000,
            },
            grandmaster_priority2: 16,
            steps_removed: 4,
            current_utc_offset: -2,
            grandmaster_identity: ClockIdentity([9, 10, 11, 12, 13, 14, 15, 16]),
        }
        .add_to(&mut builder)
        .unwrap();
        let set = builder.build();
        assert_eq!(set.tlvs().count(), 1);
        let tlv = set.tlvs().next().unwrap();
        assert_eq!(tlv.tlv_type, TlvType::CsptpStatus);
        assert_eq!(
            tlv.value,
            [
                15, 248, 41, 128, 0, 16, 0, 4, 255, 254, 9, 10, 11, 12, 13, 14, 15, 16
            ]
            .as_slice()
        );
    }
}
