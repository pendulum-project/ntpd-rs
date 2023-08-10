#![no_main]

use libfuzzer_sys::fuzz_target;
use statime::FuzzMessage;

fuzz_target!(|data: Vec<u8>| {
    let mut buf1 = [0u8; 1024];
    let mut buf2 = [0u8; 1024];
    if let Ok(a) = FuzzMessage::deserialize(&data) {
        a.serialize(&mut buf1).unwrap();
        let b = FuzzMessage::deserialize(&data).unwrap();
        b.serialize(&mut buf2).unwrap();
        assert_eq!(buf1, buf2);
    }
});
