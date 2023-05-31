#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use ntp_proto::{NoCipher, NtpPacket};

fuzz_target!(|data: Vec<u8>| {
    // packets expand by a factor of at most 4 on re-encode
    let mut buf = [0u8; 4096 * 4];
    let mut buf2 = [0u8; 4096 * 4];
    // We test here without ciphers, as that is required to make reencoding work.
    if let Ok((a, _)) = NtpPacket::deserialize(&data, &NoCipher) {
        let mut cursor = Cursor::new(buf.as_mut_slice());
        a.serialize(&mut cursor, &NoCipher).unwrap();
        let used = cursor.position();
        let slice = &buf[..used as usize];
        let b = NtpPacket::deserialize(&data, &NoCipher).unwrap().0;
        let mut cursor = Cursor::new(buf2.as_mut_slice());
        b.serialize(&mut cursor, &NoCipher).unwrap();
        let used = cursor.position();
        let slice2 = &buf2[..used as usize];
        assert_eq!(slice, slice2);
    }
});
