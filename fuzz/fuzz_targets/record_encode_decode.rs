#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtsRecord;
use std::io::Cursor;

fuzz_target!(|record: NtsRecord| {
    // fuzz inputs are at most 4096 bytes long (by default)
    let mut buffer = Cursor::new([0u8; 4096]);
    record.write(&mut buffer).unwrap();

    buffer.set_position(0);
    NtsRecord::read(&mut buffer).unwrap();
});
