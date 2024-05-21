use std::process::{Command, Output};

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
