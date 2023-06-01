#![no_main]

use libfuzzer_sys::fuzz_target;
use ntp_proto::KeySetProvider;

fuzz_target!(|data: Vec<u8>| {
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    let _ = keyset.decode_cookie_pub(&data);
});
