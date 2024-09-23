use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use algorithm::{SingleShotController, SingleShotControllerConfig};
use ntp_proto::{NtpClock, NtpDuration};

#[cfg(feature = "unstable_nts-pool")]
use crate::daemon::config::NtsPoolSourceConfig;
use crate::daemon::{
    config::{self, PoolSourceConfig},
    initialize_logging_parse_config, nts_key_provider, spawn,
    tracing::LogLevel,
};

mod algorithm;

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

impl<C: NtpClock> SingleShotController<C> {
    fn offer_clock_change(&self, offset: NtpDuration) {
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
            match self.clock.step_clock(offset) {
                Ok(_) => println!("Time updated successfully"),
                Err(_) => println!("Could not update clock, do you have the right permissions?"),
            }
        } else {
            println!("Time not updated");
        }
    }
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

    // Count number of sources
    let mut total_sources = 0;
    for source in &config.sources {
        match source {
            config::NtpSourceConfig::Standard(_)
            | config::NtpSourceConfig::Nts(_)
            | config::NtpSourceConfig::Sock(_) => total_sources += 1,
            config::NtpSourceConfig::Pool(PoolSourceConfig { count, .. }) => total_sources += count,
            #[cfg(feature = "unstable_nts-pool")]
            config::NtpSourceConfig::NtsPool(NtsPoolSourceConfig { count, .. }) => {
                total_sources += count
            }
        }
    }

    // We will need to have a keyset for the daemon
    let keyset = nts_key_provider::spawn(config.keyset).await;

    #[cfg(feature = "hardware-timestamping")]
    let clock_config = config.clock;

    #[cfg(not(feature = "hardware-timestamping"))]
    let clock_config = config::ClockConfig::default();

    ::tracing::debug!("Configuration loaded, spawning daemon jobs");
    let (main_loop_handle, _) = spawn::<SingleShotController<_>>(
        config.synchronization.synchronization_base,
        SingleShotControllerConfig {
            expected_sources: total_sources,
        },
        config.source_defaults,
        clock_config,
        &config.sources,
        &[], // No serving when operating in force sync mode
        keyset.clone(),
    )
    .await?;

    let _ = main_loop_handle.await;

    Ok(ExitCode::SUCCESS)
}
