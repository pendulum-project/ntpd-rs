#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;

fuzz_target!(|data: Vec<u8>| {
    let mut buf = [0u8; 4096];
    if let Ok(a) = NtpPacket::deserialize(&data, None) {
        let mut cursor = Cursor::new(buf.as_mut_slice());
        a.serialize(&mut cursor, None).unwrap();
        let used = cursor.position();
        let slice = &buf[..used as usize];
        assert_eq!(data, slice);
    }
});
