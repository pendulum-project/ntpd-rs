use std::{
    io::{Cursor, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use ntp_proto::{
    make_ntp_packet, Measurement, NtpAssociationMode, NtpClock, NtpDuration, NtpInstant, NtpPacket,
    PollInterval,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::daemon::{
    config::{ClockConfig, NtpSourceConfig},
    initialize_logging_parse_config,
    ntp_source::{accept_packet, AcceptResult},
    spawn::{
        nts::NtsSpawner, pool::PoolSpawner, standard::StandardSpawner, SourceCreateParameters,
        SpawnAction, Spawner,
    },
    system::MESSAGE_BUFFER_SIZE,
    tracing::LogLevel,
};

async fn spawn_once(
    mut spawner: impl Spawner + Send + 'static,
) -> Result<Vec<SourceCreateParameters>, ()> {
    let (spawn_tx, mut spawn_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);
    spawner.try_spawn(&spawn_tx).await.map_err(|e| {
        warn!("Could not spawn source: {}", e);
    })?;
    let mut events = vec![];
    spawn_rx.recv_many(&mut events, MESSAGE_BUFFER_SIZE).await;
    let sources: Vec<_> = events
        .into_iter()
        .map(|event| match event.action {
            SpawnAction::Create(params) => params,
            // _ => None,
        })
        .collect();

    Ok(sources)
}

#[tracing::instrument(skip(params, clock_config), fields(addr = %params.addr, origin = %params.normalized_addr))]
async fn send_once(
    mut params: SourceCreateParameters,
    clock_config: ClockConfig,
) -> Result<Measurement, ()> {
    debug!("Creating socket for sending request");
    let mut socket = crate::daemon::ntp_source::create_socket(
        params.addr,
        clock_config.interface,
        clock_config.timestamp_mode,
    )
    .map_err(|_| ())?;

    debug!("Constructing packet");
    let (packet, request_identifier) = make_ntp_packet(
        PollInterval::from_byte(255),
        &mut params.nts,
        params.protocol_version,
        1,
    )
    .unwrap();
    let mut buf = [0u8; 1024];

    let mut cursor = Cursor::new(&mut buf[..]);
    packet
        .serialize(
            &mut cursor,
            &params.nts.as_ref().map(|nts| nts.c2s.as_ref()),
            None,
        )
        .map_err(|_| ())?;
    let used = cursor.position();
    let packet_result = &cursor.into_inner()[..used as usize];
    let send_timestamp = clock_config.clock.now().map_err(|_| ())?;

    debug!("Sending packet");
    let send_timestamp = match socket.send(packet_result).await.map_err(|_| ())? {
        Some(ts) => crate::daemon::util::convert_net_timestamp(ts),
        None => send_timestamp,
    };

    debug!("Waiting for response");
    let res = tokio::select!(
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            warn!("timed out waiting for response");
            return Err(());
        },
        res = socket.recv(&mut buf) => res
    );

    debug!("Parsing response");
    let (packet, recv_timestamp) = match accept_packet(res, &buf, &clock_config.clock) {
        AcceptResult::Accept(packet, timestamp) => (packet, timestamp),
        _ => return Err(()),
    };
    let message =
        match NtpPacket::deserialize(packet, &params.nts.as_ref().map(|nts| nts.s2c.as_ref())) {
            Ok((packet, _)) => packet,
            Err(e) => {
                warn!("received invalid packet: {}", e);
                return Err(());
            }
        };

    debug!("Validating packet");
    // check for some message problems
    if !message.valid_server_response(request_identifier, params.nts.is_some()) {
        warn!("received invalid response");
        return Err(());
    }

    if message.is_kiss() {
        warn!("received kiss code");
        return Err(());
    }

    if message.stratum() >= 16 {
        warn!("received invalid stratum");
        return Err(());
    }

    if message.mode() != NtpAssociationMode::Server {
        warn!("received invalid mode");
        return Err(());
    }

    debug!("Creating measurement");
    // generate measurement
    Ok(Measurement::from_packet(
        &message,
        send_timestamp,
        recv_timestamp,
        NtpInstant::now(),
    ))
}

pub(crate) async fn force_sync(config: Option<PathBuf>) -> std::io::Result<ExitCode> {
    let config = initialize_logging_parse_config(Some(LogLevel::Warn), config).await;

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    if !std::io::stdin().is_terminal() {
        eprintln!("This command must be run interactively");
        return Ok(ExitCode::FAILURE);
    }

    println!("Determining current time...");

    // we ignore hardware timestamping for a force sync, we just use the defaults instead
    let clock_config = crate::daemon::config::ClockConfig::default();

    info!("Spawning sources");
    let mut measurements = vec![];
    let mut measurement_futs = vec![];
    for source_config in config.sources {
        let res = match source_config {
            NtpSourceConfig::Standard(cfg) => spawn_once(StandardSpawner::new(cfg.clone())).await,
            NtpSourceConfig::Nts(cfg) => spawn_once(NtsSpawner::new(cfg.clone())).await,
            NtpSourceConfig::Pool(cfg) => spawn_once(PoolSpawner::new(cfg.clone())).await,
            #[cfg(feature = "unstable_nts-pool")]
            NtpSourceConfig::NtsPool(cfg) => {
                spawn_once(crate::daemon::spawn::nts_pool::NtsPoolSpawner::new(
                    cfg.clone(),
                ))
                .await
            }
        };

        if let Ok(res) = res {
            for source in res {
                measurement_futs.push(tokio::spawn(send_once(source, clock_config)));
            }
        } else {
            warn!("Could not spawn sources for config");
        }
    }

    info!("Waiting for requests to complete");
    for fut in measurement_futs {
        if let Ok(Ok(measurement)) = fut.await {
            measurements.push(measurement);
        } else {
            warn!("Could not get response from source, ignoring");
        }
    }

    info!("Got all measurements, calculating average offset");
    let offsets = measurements
        .into_iter()
        .map(|m| m.offset.to_seconds())
        .collect::<Vec<_>>();

    // calculate the mean offset iteratively
    let mut avg = 0.0;
    let mut t = 1;
    for offset in offsets {
        avg += (offset - avg) / (t as f64);
        t += 1;
    }
    let avg_offset = NtpDuration::from_seconds(avg);

    offer_clock_change(avg_offset, clock_config);

    Ok(ExitCode::SUCCESS)
}

fn human_readable_duration(abs_offset: f64) -> String {
    let mut offset = abs_offset;
    let mut res = String::new();
    if offset >= 86400.0 {
        let days = (offset / 86400.0).floor() as u64;
        offset -= days as f64 * 86400.0;
        res.push_str(&format!("{} day(s) ", days));
    }
    if offset >= 3600.0 {
        let hours = (offset / 3600.0).floor() as u64;
        offset -= hours as f64 * 3600.0;
        res.push_str(&format!("{} hour(s) ", hours));
    }
    if offset >= 60.0 {
        let minutes = (offset / 60.0).floor() as u64;
        offset -= minutes as f64 * 60.0;
        res.push_str(&format!("{} minute(s) ", minutes));
    }
    if offset >= 1.0 {
        res.push_str(&format!("{:.0} second(s)", offset));
    }
    res
}

fn try_date_display(offset: NtpDuration) -> Option<String> {
    let time = SystemTime::now();
    let since_epoch = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = since_epoch + (offset.to_seconds() as u64);

    std::process::Command::new("date")
        .arg("-d")
        .arg(format!("@{}", ts))
        .arg("+%c")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
}

fn offer_clock_change(offset: NtpDuration, clock_config: ClockConfig) {
    let offset_ms = offset.to_seconds();
    if offset.abs() < NtpDuration::from_seconds(1.0) {
        println!("Your clock is already within 1s of the correct time");
        return;
    }

    if let Some(s) = try_date_display(NtpDuration::ZERO) {
        println!("The current local time is: {s}");
    }

    if let Some(s) = try_date_display(offset) {
        println!("It looks like the time should be: {s}");
    }

    if offset < NtpDuration::ZERO {
        println!(
            "It looks like your clock is ahead by {}",
            human_readable_duration(-offset_ms)
        );
    } else {
        println!(
            "It looks like your clock is behind by {}",
            human_readable_duration(offset_ms)
        );
    }
    println!("Please validate externally that this offset is correct");
    print!("Do you want to update your local clock? [y/N] ");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
        match clock_config.clock.step_clock(offset) {
            Ok(_) => println!("Time updated successfully"),
            Err(_) => println!("Could not update clock, do you have the right permissions?"),
        }
    } else {
        println!("Time not updated");
    }
}
