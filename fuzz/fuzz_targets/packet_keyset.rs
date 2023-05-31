#![no_main]

use libfuzzer_sys::fuzz_target;
use ntp_proto::{KeySetProvider, NtpPacket};

fuzz_target!(|data: Vec<u8>| {
    // Can't test reencoding because of the keyset
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    let _ = NtpPacket::deserialize(&data, keyset.as_ref());
});
