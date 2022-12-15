#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;
use pretty_assertions::assert_eq;
use std::io::Cursor;

fuzz_target!(|data: Vec<u8>| {
    let mut buf = [0u8; 4096];
    if let Ok(a) = NtpPacket::deserialize_without_decryption(&data) {
        let mut cursor = Cursor::new(buf.as_mut_slice());
        a.serialize_without_encryption(&mut cursor).unwrap();
        let used = cursor.position();
        let slice = &buf[..used as usize];
        assert_eq!(data, slice);
    }
});
