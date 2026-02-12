#![no_main]
#![expect(clippy::type_complexity)]

use std::{
    borrow::Cow,
    io::{Cursor, Write},
    net::IpAddr,
    time::Duration,
};

use libfuzzer_sys::fuzz_target;
use ntp_proto::{
    test_cookie,
    v5::{BloomFilter, ServerId},
    EncryptResult, ExtensionField, ExtensionHeaderVersion, FilterAction, FilterList,
    HandleInnerData, KeySetProvider, NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp,
    NtpVersion, ReferenceId, Server, ServerConfig, ServerReason, ServerResponse, ServerStatHandler,
    SystemSnapshot, TimeSnapshot,
};
use rand::{rngs::StdRng, set_thread_rng, SeedableRng};

const fn next_multiple_of(lhs: u16, rhs: u16) -> u16 {
    match lhs % rhs {
        0 => lhs,
        r => lhs + (rhs - r),
    }
}

fuzz_target!(|parts: (
    Vec<u8>,
    u64,
    [u8; 4],
    Option<(Vec<u8>, Vec<u8>, Vec<u8>, ExtensionHeaderVersion)>
)| {
    set_thread_rng(StdRng::seed_from_u64(parts.1));

    // Can't test reencoding because of the keyset
    let provider = KeySetProvider::dangerous_new_deterministic(1);

    let keyset = provider.get();

    let mut cursor = Cursor::new([0u8; 8192]);

    let message = if let Some(encrypted) = parts.3 {
        // Build packet
        let _ = cursor.write_all(&parts.0);
        let cookie = test_cookie();
        let enc_cookie = keyset.encode_cookie_pub(&cookie);
        let _ = ExtensionField::NtsCookie(Cow::Borrowed(&enc_cookie)).serialize_pub(
            &mut cursor,
            4,
            encrypted.3,
        );
        let _ = cursor.write_all(&encrypted.0);

        let mut ciphertext = encrypted.1.clone();
        ciphertext.resize(ciphertext.len() + 32, 0);
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = cookie
            .c2s
            .encrypt(
                &mut ciphertext,
                encrypted.1.len(),
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
        let _ = cursor.write_all(&encrypted.2);
        cursor.get_ref()
    } else {
        let _ = cursor.write_all(&parts.0);
        cursor.get_ref()
    };

    let denylist = FilterList {
        filter: vec!["1.0.0.0/24".parse().unwrap()],
        action: FilterAction::Ignore,
    };

    let allowlist = FilterList {
        filter: vec!["1.0.0.0/8".parse().unwrap()],
        action: FilterAction::Deny,
    };

    let ip = IpAddr::from(parts.2);

    let mut server = Server::new(
        ServerConfig {
            denylist,
            allowlist,
            rate_limiting_cache_size: 0,
            rate_limiting_cutoff: Duration::from_secs(1),
            require_nts: None,
            accepted_versions: vec![NtpVersion::V3, NtpVersion::V4, NtpVersion::V5],
        },
        TestClock {
            cur: NtpTimestamp::from_seconds_nanos_since_ntp_era(100, 0),
        },
        SystemSnapshot {
            stratum: 1,
            reference_id: ReferenceId::NONE,
            accumulated_steps_threshold: Some(NtpDuration::from_seconds(0.0)),
            time_snapshot: TimeSnapshot {
                precision: NtpDuration::from_seconds(0.00001),
                root_delay: NtpDuration::from_seconds(0.01),
                root_variance_base_time: NtpTimestamp::from_seconds_nanos_since_ntp_era(90, 0),
                root_variance_base: 1e-9,
                root_variance_linear: 0.0,
                root_variance_quadratic: 0.0,
                root_variance_cubic: 0.0,
                leap_indicator: NtpLeapIndicator::NoWarning,
                accumulated_steps: NtpDuration::from_seconds(0.0),
            },
            bloom_filter: BloomFilter::new(),
            server_id: ServerId::new(&mut rand::thread_rng()),
        },
        keyset,
    );

    let mut buffer = [0u8; 8192];

    if let Ok(HandleInnerData {
        packet,
        cipher,
        desired_size,
        ..
    }) = server.fuzz_handle_inner(
        ip,
        NtpTimestamp::from_seconds_nanos_since_ntp_era(99, 900000000),
        message,
        &mut TestStatHandler,
    ) {
        let mut cursor = Cursor::new(&mut buffer[..message.len()]);
        assert!(packet
            .serialize(&mut cursor, &cipher.as_deref(), desired_size)
            .is_ok());
    }
});

#[derive(Debug, Clone, Default)]
struct TestClock {
    cur: NtpTimestamp,
}

impl NtpClock for TestClock {
    type Error = std::time::SystemTimeError;

    fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
        Ok(self.cur)
    }

    fn set_frequency(&self, _freq: f64) -> Result<NtpTimestamp, Self::Error> {
        panic!("Shouldn't be called by server");
    }

    fn get_frequency(&self) -> Result<f64, Self::Error> {
        Ok(0.0)
    }

    fn step_clock(&self, _offset: NtpDuration) -> Result<NtpTimestamp, Self::Error> {
        panic!("Shouldn't be called by server");
    }

    fn disable_ntp_algorithm(&self) -> Result<(), Self::Error> {
        panic!("Shouldn't be called by server");
    }

    fn error_estimate_update(
        &self,
        _est_error: NtpDuration,
        _max_error: NtpDuration,
    ) -> Result<(), Self::Error> {
        panic!("Shouldn't be called by server");
    }

    fn status_update(&self, _leap_status: NtpLeapIndicator) -> Result<(), Self::Error> {
        panic!("Shouldn't be called by source");
    }
}

#[derive(Debug, Default)]
struct TestStatHandler;

impl ServerStatHandler for TestStatHandler {
    fn register(
        &mut self,
        _version: u8,
        _nts: bool,
        _reason: ServerReason,
        _response: ServerResponse,
    ) {
    }
}
