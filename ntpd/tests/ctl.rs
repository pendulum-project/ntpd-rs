use std::{fs::File, io::Write, os::unix::net::UnixListener, process::Command, thread::spawn};

fn contains_bytes(mut haystack: &[u8], needle: &[u8]) -> bool {
    while haystack.len() >= needle.len() {
        if haystack.starts_with(needle) {
            return true;
        }
        haystack = &haystack[1..];
    }
    false
}

#[test]
fn test_validate() {
    let result = Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args([
            "validate",
            "-c",
            &format!(
                "{}/testdata/config/invalid.toml",
                env!("CARGO_MANIFEST_DIR")
            ),
        ])
        .output()
        .unwrap();
    assert!(contains_bytes(
        &result.stderr,
        b"unknown field `does-not-exist`"
    ));
    assert_eq!(result.status.code(), Some(1));

    let result = Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args([
            "validate",
            "-c",
            &format!("{}/../ntp.toml", env!("CARGO_MANIFEST_DIR")),
        ])
        .output()
        .unwrap();
    assert!(contains_bytes(&result.stderr, b"good"));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_status() {
    let _ = std::fs::remove_file(format!(
        "{}/status_test_socket",
        env!("CARGO_TARGET_TMPDIR")
    ));
    let socket = UnixListener::bind(format!(
        "{}/status_test_socket",
        env!("CARGO_TARGET_TMPDIR")
    ))
    .unwrap();
    spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        stream.write_all(r#"{"system":{"stratum":3,"reference_id":3243240718,"accumulated_steps_threshold":null,"poll_interval":4,"precision":3.814697266513178e-6,"root_delay":0.004877627828362777,"root_dispersion":0.0004254912492878482,"leap_indicator":"Unknown","accumulated_steps":0.002842015820285775},"peers":[{"Observable":{"offset":0.00031014974236259,"uncertainty":0.000050753355038062054,"delay":0.0036874422812106654,"remote_delay":0.0011901855471521117,"remote_uncertainty":0.019378662113886946,"last_update":{"timestamp":16760961381687937893},"unanswered_polls":0,"poll_interval":4,"address":"ntpd-rs.pool.ntp.org:123","id":3}},{"Observable":{"offset":0.0003928544466367118,"uncertainty":0.00005519413390550626,"delay":0.004574143328837618,"remote_delay":0.001602172851935535,"remote_uncertainty":0.0004425048829155287,"last_update":{"timestamp":16760961379467247810},"unanswered_polls":0,"poll_interval":4,"address":"ntpd-rs.pool.ntp.org:123","id":1}},{"Observable":{"offset":0.00043044891218432433,"uncertainty":0.00005691661500765863,"delay":0.004752595444385101,"remote_delay":0.001602172851935535,"remote_uncertainty":0.03733825684463099,"last_update":{"timestamp":16760961371126323413},"unanswered_polls":0,"poll_interval":4,"address":"ntpd-rs.pool.ntp.org:123","id":2}},{"Observable":{"offset":-0.0019038764298669707,"uncertainty":0.00016540312212086355,"delay":0.007399475902179134,"remote_delay":0.01371765137038139,"remote_uncertainty":0.0014495849612750078,"last_update":{"timestamp":16760961373841849724},"unanswered_polls":0,"poll_interval":4,"address":"ntpd-rs.pool.ntp.org:123","id":4}}],"servers":[]}"#.as_bytes()).unwrap();
    });
    let mut config = File::create(format!(
        "{}/status_test_config",
        env!("CARGO_TARGET_TMPDIR")
    ))
    .unwrap();
    config
        .write_all(
            format!(
                r#"[observability]
observation-path = "{}/status_test_socket"

[[peer]]
mode = "pool"
address = "ntpd-rs.pool.ntp.org"
count = 4
"#,
                env!("CARGO_TARGET_TMPDIR")
            )
            .as_bytes(),
        )
        .unwrap();
    drop(config);

    let result = Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args([
            "status",
            "-c",
            &format!("{}/status_test_config", env!("CARGO_TARGET_TMPDIR")),
        ])
        .output()
        .unwrap();

    assert!(contains_bytes(&result.stdout, b"ntpd-rs.pool.ntp.org"));
    assert!(contains_bytes(
        &result.stdout,
        "0.000310±0.000051(±0.003687)s".as_bytes()
    ));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_version() {
    let result = Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args(["-v"])
        .output()
        .unwrap();
    assert!(contains_bytes(
        &result.stderr,
        dbg!(env!("CARGO_PKG_VERSION")).as_bytes()
    ));
    assert_eq!(result.status.code(), Some(0));
}

#[test]
fn test_help() {
    let result = Command::new(env!("CARGO_BIN_EXE_ntp-ctl"))
        .args(["-h"])
        .output()
        .unwrap();
    assert!(contains_bytes(&result.stdout, b"usage"));
    assert_eq!(result.status.code(), Some(0));
}
