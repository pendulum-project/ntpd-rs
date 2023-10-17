#![no_main]

use std::{
    borrow::Cow,
    io::{Cursor, Write},
};

use libfuzzer_sys::fuzz_target;
use ntp_proto::{test_cookie, EncryptResult, ExtensionField, ExtensionHeaderVersion, KeySetProvider, NtpPacket};
use rand::{rngs::StdRng, set_thread_rng, SeedableRng};

const fn next_multiple_of(lhs: u16, rhs: u16) -> u16 {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

fuzz_target!(|parts: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u64, ExtensionHeaderVersion)| {
    set_thread_rng(StdRng::seed_from_u64(parts.4));

    // Can't test reencoding because of the keyset
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    // Build packet
    let mut cursor = Cursor::new([0u8; 8192]);
    let _ = cursor.write_all(&parts.0);
    let cookie = test_cookie();
    let enc_cookie = keyset.encode_cookie_pub(&cookie);
    let _ = ExtensionField::NtsCookie(Cow::Borrowed(&enc_cookie)).serialize_pub(&mut cursor, 4, parts.5);
    let _ = cursor.write_all(&parts.1);

    let mut ciphertext = parts.2.clone();
    ciphertext.resize(ciphertext.len() + 32, 0);
    let EncryptResult {
        nonce_length,
        ciphertext_length,
    } = cookie
        .c2s
        .encrypt(
            &mut ciphertext,
            parts.2.len(),
            &cursor.get_ref()[..cursor.position() as usize],
        )
        .unwrap();

    let _ = cursor.write_all(&0x404u16.to_be_bytes());
    let _ = cursor.write_all(
        &(8 + next_multiple_of((nonce_length + ciphertext_length) as u16, 4)).to_be_bytes(),
    );
    let _ = cursor.write_all(&(nonce_length as u16).to_be_bytes());
    let _ = cursor.write_all(&(ciphertext_length as u16).to_be_bytes());
    let _ = cursor.write_all(&ciphertext);
    let _ = cursor.write_all(&parts.3);

    let _ = NtpPacket::deserialize(cursor.get_ref(), keyset.as_ref());
});
