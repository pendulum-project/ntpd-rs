#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use ntp_proto::NtpPacket;

fuzz_target!(|data: Vec<u8>| {
    // Output can be up to 4 times larger than input
    let mut buf = [0u8; 4096 * 4];
    let mut buf2 = [0u8; 4096 * 4];
    if let Ok(a) = NtpPacket::deserialize(&data, None) {
        let mut cursor = Cursor::new(buf.as_mut_slice());
        a.serialize(&mut cursor, None).unwrap();
        let used = cursor.position();
        let slice = &buf[..used as usize];
        let b = NtpPacket::deserialize(slice, None).unwrap();
        let mut cursor2 = Cursor::new(buf2.as_mut_slice());
        b.serialize(&mut cursor2, None).unwrap();
        let used2 = cursor2.position();
        let slice2 = &buf[..used2 as usize];
        assert_eq!(slice, slice2);
    }
});
