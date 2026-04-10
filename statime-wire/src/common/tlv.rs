use core::iter::FusedIterator;

use crate::Error;

/// A builder that can be used to create [`TlvSet`]
#[derive(PartialEq, Eq)]
pub struct TlvSetBuilder<'a> {
    buffer: &'a mut [u8],
    used: usize,
}

impl<'a> TlvSetBuilder<'a> {
    /// Create a new builder with the given buffer as backing storage
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, used: 0 }
    }

    /// Add a TLV to the builder.
    ///
    /// # Errors
    /// Fails when the remaining buffer is too small for the TLV, or
    /// when the TLV itself is larger than 2^16 bytes.
    pub fn add(&mut self, tlv: &Tlv<'_>) -> Result<(), Error> {
        tlv.serialize(&mut self.buffer[self.used..])?;
        self.used += tlv.wire_size();
        Ok(())
    }

    /// Create the actual [`TlvSet`]
    #[must_use]
    pub fn build(self) -> TlvSet<'a> {
        TlvSet {
            bytes: &self.buffer[..self.used],
        }
    }
}

/// A set of TLVs that can be iterated over.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TlvSet<'a> {
    bytes: &'a [u8],
}

impl core::fmt::Debug for TlvSet<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlvSet")
            .field("wire_size", &self.wire_size())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl<'a> TlvSet<'a> {
    pub(crate) fn wire_size(&self) -> usize {
        // tlv should be an even number of octets!
        debug_assert_eq!(self.bytes.len() % 2, 0);

        self.bytes.len()
    }

    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        buffer
            .get_mut(..self.bytes.len())
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(self.bytes);

        Ok(self.bytes.len())
    }

    pub(crate) fn deserialize(mut buffer: &'a [u8]) -> Result<Self, Error> {
        let original = buffer;
        let mut total_length = 0;

        while buffer.len() > 4 {
            let _tlv_type = TlvType::from_primitive(u16::from_be_bytes([buffer[0], buffer[1]]));
            let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;

            if !length.is_multiple_of(2) {
                return Err(Error::Invalid);
            }

            buffer = buffer.get(4 + length..).ok_or(Error::BufferTooShort)?;

            total_length += 4 + length;
        }

        if !buffer.is_empty() {
            return Err(Error::BufferTooShort);
        }

        Ok(Self {
            bytes: &original[..total_length],
        })
    }

    /// Iterator over all TLVs in the set which need to be propagated when
    /// attached to announce messages.
    pub fn announce_propagate_tlvs(&self) -> impl Iterator<Item = Tlv<'a>> + 'a {
        self.tlvs().filter(|tlv| tlv.tlv_type.announce_propagate())
    }

    /// Iterator over all TLVs in the set.
    pub fn tlvs(&self) -> impl Iterator<Item = Tlv<'a>> + 'a {
        TlvSetIterator { buffer: self.bytes }
    }
}

#[derive(Debug)]
struct TlvSetIterator<'a> {
    buffer: &'a [u8],
}

impl<'a> Iterator for TlvSetIterator<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() <= 4 {
            debug_assert_eq!(self.buffer.len(), 0);
            return None;
        }

        // we've validated the buffer; this should never fail!
        let tlv = Tlv::deserialize(self.buffer).unwrap();

        self.buffer = &self.buffer[tlv.wire_size()..];

        Some(tlv)
    }
}

impl FusedIterator for TlvSetIterator<'_> {}

/// A single TLV that can be afixed to a PTP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The type of this TLV.
    pub tlv_type: TlvType,
    /// The actual contents of the TLV.
    ///
    /// Note that this is of type [`Cow<'a, [u8]>`](std::borrow::Cow) instead
    /// when the standard library feature is enabled.
    #[cfg(not(feature = "std"))]
    pub value: &'a [u8],
    /// The actual contents of the TLV.
    ///
    /// Note that this is of type `&'a [u8]` instead when the standard library
    /// feature is disabled.
    #[cfg(feature = "std")]
    pub value: std::borrow::Cow<'a, [u8]>,
}

impl<'a> Tlv<'a> {
    pub(crate) fn wire_size(&self) -> usize {
        4 + self.value.len()
    }

    pub(crate) fn serialize(&self, buffer: &mut [u8]) -> Result<(), Error> {
        let len = u16::try_from(self.value.len()).map_err(|_| Error::Invalid)?;
        buffer
            .get_mut(0..2)
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(&self.tlv_type.to_primitive().to_be_bytes());
        buffer
            .get_mut(2..4)
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(&len.to_be_bytes());
        buffer
            .get_mut(4..)
            .ok_or(Error::BufferTooShort)?
            .get_mut(..self.value.len())
            .ok_or(Error::BufferTooShort)?
            .copy_from_slice(self.value.as_ref());

        Ok(())
    }

    fn deserialize(buffer: &'a [u8]) -> Result<Self, Error> {
        if buffer.len() < 4 {
            return Err(Error::BufferTooShort);
        }

        let tlv_type = TlvType::from_primitive(u16::from_be_bytes([buffer[0], buffer[1]]));
        let length = u16::from_be_bytes([buffer[2], buffer[3]]);

        // Parse TLV content / value
        if buffer.len() < 4 + length as usize {
            return Err(Error::BufferTooShort);
        }

        let value = &buffer[4..][..length as usize];
        Ok(Self {
            tlv_type,
            value: value.into(),
        })
    }

    /// Ensure this TLV owns its storage.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn into_owned(self) -> Tlv<'static> {
        Tlv {
            tlv_type: self.tlv_type,
            value: self.value.into_owned().into(),
        }
    }
}

/// The type of a given TLV.
///
/// For more detials, see *IEEE1588-2019 section 14.1.1 / Table 52*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
    /// Reserved for future use
    Reserved(u16),
    /// The management TLV.
    Management,
    #[expect(clippy::doc_markdown)]
    /// The ManagementErrorStatus TLV
    ManagementErrorStatus,
    /// An organization extension TLV.
    ///
    /// These have an additional set of identifiers identifying the actual type
    /// in the TLV data itself.
    OrganizationExtension,
    /// A TLV containing a request for unicast transmission.
    RequestUnicastTransmission,
    /// A grant for unicast transmission.
    GrantUnicastTransmission,
    /// A request to cancel unicast transmission.
    CancelUnicastTransmission,
    /// Acknowledgement of unicast transmission cancelation.
    AcknowledgeCancelUnicastTransmission,
    /// Path tracing data.
    PathTrace,
    /// Information for computing a different timescale.
    AlternateTimeOffsetIndicator,
    /// TLV types used in previous versions of the standard.
    Legacy(u16),
    /// TLV identifiers inteded for experimentation.
    Experimental(u16),
    /// An organization extension TLV that needs to be propagated on announce messages.
    ///
    /// These have an additional set of identifiers identifying the actual type
    /// in the TLV data itself.
    OrganizationExtensionPropagate,
    /// Enhanced accury metrics.
    EnhancedAccuracyMetrics,
    /// An organization extension TLV that must not be propagated on announce messages.
    ///
    /// These have an additional set of identifiers identifying the actual type
    /// in the TLV data itself.
    OrganizationExtensionDoNotPropagate,
    /// Data for Layer 1 synchronization.
    L1Sync,
    /// Information about port communication capabilities.
    PortCommunicationAvailability,
    /// Protocol address of the sending PTP port
    ProtocolAddress,
    /// Timing data on received messages from time receiver monitoring.
    SlaveRxSyncTimingData,
    /// Computed data from time receiver monitoring.
    SlaveRxSyncComputedData,
    /// Timing data on sent message from time receiver monitoring.
    SlaveTxEventTimestamps,
    /// Cumulative frequency transfer data.
    CumulativeRateRatio,
    /// Padding.
    Pad,
    /// Message authentication.
    Authentication,
}

impl TlvType {
    #[must_use]
    pub(crate) fn to_primitive(self) -> u16 {
        match self {
            Self::Management => 0x0001,
            Self::ManagementErrorStatus => 0x0002,
            Self::OrganizationExtension => 0x0003,
            Self::RequestUnicastTransmission => 0x0004,
            Self::GrantUnicastTransmission => 0x0005,
            Self::CancelUnicastTransmission => 0x0006,
            Self::AcknowledgeCancelUnicastTransmission => 0x0007,
            Self::PathTrace => 0x0008,
            Self::AlternateTimeOffsetIndicator => 0x0009,
            Self::OrganizationExtensionPropagate => 0x4000,
            Self::EnhancedAccuracyMetrics => 0x4001,
            Self::OrganizationExtensionDoNotPropagate => 0x8000,
            Self::L1Sync => 0x8001,
            Self::PortCommunicationAvailability => 0x8002,
            Self::ProtocolAddress => 0x8003,
            Self::SlaveRxSyncTimingData => 0x8004,
            Self::SlaveRxSyncComputedData => 0x8005,
            Self::SlaveTxEventTimestamps => 0x8006,
            Self::CumulativeRateRatio => 0x8007,
            Self::Pad => 0x8008,
            Self::Authentication => 0x8009,
            Self::Reserved(value) | Self::Legacy(value) | Self::Experimental(value) => value,
        }
    }

    #[must_use]
    pub(crate) fn from_primitive(value: u16) -> Self {
        match value {
            0x0000
            | 0x000a..=0x1fff
            | 0x2030..=0x3fff
            | 0x4002..=0x7eff
            | 0x800a..=0xffef
            | 0xfff0..=0xffff => Self::Reserved(value),
            0x2000..=0x2003 => Self::Legacy(value),
            0x2004..=0x202f | 0x7f00..=0x7fff => Self::Experimental(value),
            0x0001 => Self::Management,
            0x0002 => Self::ManagementErrorStatus,
            0x0003 => Self::OrganizationExtension,
            0x0004 => Self::RequestUnicastTransmission,
            0x0005 => Self::GrantUnicastTransmission,
            0x0006 => Self::CancelUnicastTransmission,
            0x0007 => Self::AcknowledgeCancelUnicastTransmission,
            0x0008 => Self::PathTrace,
            0x0009 => Self::AlternateTimeOffsetIndicator,
            0x4000 => Self::OrganizationExtensionPropagate,
            0x4001 => Self::EnhancedAccuracyMetrics,
            0x8000 => Self::OrganizationExtensionDoNotPropagate,
            0x8001 => Self::L1Sync,
            0x8002 => Self::PortCommunicationAvailability,
            0x8003 => Self::ProtocolAddress,
            0x8004 => Self::SlaveRxSyncTimingData,
            0x8005 => Self::SlaveRxSyncComputedData,
            0x8006 => Self::SlaveTxEventTimestamps,
            0x8007 => Self::CumulativeRateRatio,
            0x8008 => Self::Pad,
            0x8009 => Self::Authentication,
        }
    }

    /// True if this message should be propagated by a boundary clock if it is
    /// attached to an announce message
    #[must_use]
    pub fn announce_propagate(self) -> bool {
        matches!(self.to_primitive(), 0x0008 | 0x0009 | 0x4000..=0x7fff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_management() {
        let tlv = Tlv {
            tlv_type: TlvType::Management,
            value: (&b"hello!"[..]).into(),
        };

        let mut buffer = [0; 256];
        tlv.serialize(&mut buffer).unwrap();

        let n = tlv.wire_size();
        assert_eq!(n, 10);

        let decoded = Tlv::deserialize(&buffer[..n]).unwrap();

        assert_eq!(tlv, decoded);
    }

    #[test]
    fn parse_announce_propagate_messages() {
        let mut alloc = [0; 256];
        let mut buffer = &mut alloc[..];

        let tlv1 = Tlv {
            tlv_type: TlvType::Management,
            value: (&b"hello!"[..]).into(),
        };
        tlv1.serialize(buffer).unwrap();
        buffer = &mut buffer[tlv1.wire_size()..];
        assert!(!tlv1.tlv_type.announce_propagate());

        let tlv2 = Tlv {
            tlv_type: TlvType::PathTrace,
            value: (&b"PathTrace!"[..]).into(),
        };
        tlv2.serialize(buffer).unwrap();
        buffer = &mut buffer[tlv2.wire_size()..];
        assert!(tlv2.tlv_type.announce_propagate());

        let tlv3 = Tlv {
            tlv_type: TlvType::OrganizationExtensionPropagate,
            value: (&b"OrganizationExtensionPropagate"[..]).into(),
        };
        tlv3.serialize(buffer).unwrap();
        buffer = &mut buffer[tlv3.wire_size()..];
        assert!(tlv3.tlv_type.announce_propagate());

        let _ = buffer;

        let buffer = &mut alloc[..tlv1.wire_size() + tlv2.wire_size() + tlv3.wire_size()];
        let tlv_set = TlvSet::deserialize(buffer).unwrap();
        let mut it = tlv_set.announce_propagate_tlvs();

        assert_eq!(it.next(), Some(tlv2));
        assert_eq!(it.next(), Some(tlv3));
        assert_eq!(it.next(), None);
    }
}
