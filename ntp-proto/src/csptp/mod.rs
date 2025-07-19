use std::io::Cursor;

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
}
