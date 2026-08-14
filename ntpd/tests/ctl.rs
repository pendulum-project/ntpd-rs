#![allow(missing_docs)]

use std::{
    io::Write,
    os::unix::net::UnixListener,
    process::{Command, Output},
    thread::spawn,
};

fn contains_bytes(mut haystack: &[u8], needle: &[u8]) -> bool {
    while haystack.len() >= needle.len() {
        if haystack.starts_with(needle) {
            return true;
        }
        haystack = &haystack[1..];
    }
    false
}

fn test_ntp_ctl_output(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args(args)
        .output()
        .unwrap()
}

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const CARGO_TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");

#[test]
fn test_validate_bad() {
    let result = test_ntp_ctl_output(&[
        "validate",
        "-c",
        &format!("{CARGO_MANIFEST_DIR}/testdata/config/invalid.toml",),
    ]);

    assert!(contains_bytes(
        &result.stderr,
        b"unknown field `does-not-exist`"
    ));
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn test_validate_good() {
    let result = test_ntp_ctl_output(&[
        "validate",
        "-c",
        &format!("{CARGO_MANIFEST_DIR}/../ntp.toml"),
    ]);

    assert!(contains_bytes(&result.stderr, b"good"));
    assert_eq!(result.status.code(), Some(0));
}

const EXAMPLE_SOCKET_OUTPUT: &str = r#"{"program":{"version":"2.0.0-alpha.20260715","build_commit":"622dff30855f413351deb336b7aee3aba490fea3-dirty","build_commit_date":"2026-08-14","uptime_seconds":285.599832511,"now":{"timestamp":17161415454042162558}},"system":{"precision":{"upper":0,"lower":18446744073},"root_delay":{"upper":0,"lower":141992056892424192},"root_variance_base_time":{"upper":1786714564,"lower":5710806022495404032},"root_variance_base":5.921928360305701e-9,"root_variance_linear":3.18717266009306e-11,"root_variance_quadratic":4.933965675389926e-13,"root_variance_cubic":1.0000000000000001e-16,"leap_indicator":"None","accumulated_steps":{"upper":0,"lower":1116179974944980992},"accumulated_steps_threshold":null,"stratum":2,"reference_id":764032830},"sources":[{"offset":-0.00015369383621814052,"uncertainty":0.00011030817406957694,"delay":0.007697404829714774,"remote_delay":0.0,"remote_uncertainty":0.0,"last_update":{"timestamp":17161415433140624338},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"45.138.55.62:123","id":3},{"offset":-0.0036293484744684187,"uncertainty":0.00016058492477996855,"delay":0.014973421584575769,"remote_delay":0.015197753909788503,"remote_uncertainty":0.0013122558596805334,"last_update":{"timestamp":17161415429262920339},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"188.68.34.173:123","id":4},{"offset":0.0002758931369231765,"uncertainty":0.00011130957866816539,"delay":0.004301442532870323,"remote_delay":0.0040740966806360746,"remote_uncertainty":0.023086547856937756,"last_update":{"timestamp":17161415427304347156},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"174.138.107.7:123","id":1},{"offset":0.000882254447993416,"uncertainty":0.00011676875877118873,"delay":0.004716757453213622,"remote_delay":0.039077758798161,"remote_uncertainty":0.02990722656946332,"last_update":{"timestamp":17161415430949824854},"unanswered_polls":0,"poll_interval":4,"nts_cookies":null,"name":"ntpd-rs.pool.ntp.org:123","address":"95.211.123.72:123","id":2}],"servers":[]}"#;

#[test]
fn test_status() {
    let _ = std::fs::remove_file(format!("{CARGO_TARGET_TMPDIR}/status_test_socket"));
    let socket = UnixListener::bind(format!("{CARGO_TARGET_TMPDIR}/status_test_socket")).unwrap();

    spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream
            .write_all(&(EXAMPLE_SOCKET_OUTPUT.len() as u64).to_be_bytes())
            .unwrap();
        stream.write_all(EXAMPLE_SOCKET_OUTPUT.as_bytes()).unwrap();
    });

    let test_config_contents = format!(
        r#"[observability]
observation-path = "{CARGO_TARGET_TMPDIR}/status_test_socket"

[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4
"#
    );

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/status_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["status", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stdout, b"ntpd-rs.pool.ntp.org"));
    assert!(contains_bytes(&result.stdout, "+0.000276".as_bytes()));
    assert!(contains_bytes(&result.stdout, "±0.000111".as_bytes()));
    assert!(contains_bytes(&result.stdout, "±0.004301".as_bytes()));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_version() {
    let result = test_ntp_ctl_output(&["-v"]);

    assert!(contains_bytes(
        &result.stderr,
        env!("CARGO_PKG_VERSION").as_bytes()
    ));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_help() {
    let result = test_ntp_ctl_output(&["-h"]);

    assert!(contains_bytes(&result.stdout, b"usage"));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_bad_reference_id() {
    // Reference ID is too long

    let test_config_contents = r#"
[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4

[synchronization]
local-stratum = 1
reference-id = "TOO_LONG"
"#;

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/reference_id_bad_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["validate", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stderr, b"up to 4-character string"));
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn test_good_reference_id() {
    let test_config_contents = r#"
[[source]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4

[synchronization]
local-stratum = 1
reference-id = "GPS"
"#;

    let test_config_path = format!("{CARGO_TARGET_TMPDIR}/reference_id_good_test_config");
    std::fs::write(&test_config_path, test_config_contents.as_bytes()).unwrap();

    let result = test_ntp_ctl_output(&["validate", "-c", &test_config_path]);

    assert!(contains_bytes(&result.stderr, b"good"));
    assert_eq!(result.status.code(), Some(0));
}
