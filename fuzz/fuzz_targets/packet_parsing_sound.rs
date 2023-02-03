#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;

fuzz_target!(|data: Vec<u8>| {
    // packets expand by a factor of at most 4 on re-encode
    let mut buf = [0u8; 4096 * 4];
    let mut buf2 = [0u8; 4096 * 4];
    if let Ok(a) = NtpPacket::deserialize(&data, &()) {
        let mut cursor = Cursor::new(buf.as_mut_slice());
        a.serialize(&mut cursor, &()).unwrap();
        let used = cursor.position();
        let slice = &buf[..used as usize];
        let b = NtpPacket::deserialize(&data, &()).unwrap();
        let mut cursor = Cursor::new(buf2.as_mut_slice());
        b.serialize(&mut cursor, &()).unwrap();
        let used = cursor.position();
        let slice2 = &buf2[..used as usize];
        assert_eq!(slice, slice2);
    }
});
