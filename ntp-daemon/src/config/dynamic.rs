use crate::sockets::create_unix_socket;
use crate::tracing::ReloadHandle;
use ntp_proto::{NtpDuration, StepThreshold, SystemConfig};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::error;
use tracing_subscriber::EnvFilter;

use clap::Args;
use serde::{Deserialize, Serialize};

use super::ConfigureConfig;

fn parse_env_filter(input: &str) -> Result<String, tracing_subscriber::filter::ParseError> {
    // run the parser to error on any invalid input
    let _ = EnvFilter::builder().with_regex(false).parse(input)?;

    // but we actually send `String` over, because it is (De)Serialize
    Ok(input.to_string())
}

#[derive(Debug, Args, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// Change the log filter
    #[arg(long, value_parser = parse_env_filter)]
    pub log_filter: Option<String>,

    /// The maximum duration in seconds the system clock is allowed to change in a single jump
    /// before we conclude something is seriously wrong. This is used to limit
    /// the changes to the clock to reasonable ammounts, and stop issues with
    /// remote servers from causing us to drift too far.
    ///
    /// Note that this is not used during startup. To limit system clock changes
    /// during startup, use startup_panic_threshold
    #[arg(long)]
    pub panic_threshold: Option<f64>,
}

// Deal with reloading not being possible during testing.
pub trait LogReloader {
    fn update_log(&self, f: EnvFilter);
}

impl LogReloader for ReloadHandle {
    fn update_log(&self, f: EnvFilter) {
        self.modify(|l| *l.filter_mut() = f).unwrap();
    }
}

pub async fn spawn<H: LogReloader + Send + 'static>(
    config: ConfigureConfig,
    system_config: Arc<RwLock<SystemConfig>>,
    log_reload_handle: H,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let result = dynamic_configuration(config, system_config, log_reload_handle).await;
        if let Err(ref e) = result {
            error!("Abnormal termination of dynamic configurator: {}", e);
        }
        result
    })
}

async fn dynamic_configuration<H: LogReloader>(
    config: ConfigureConfig,
    system_config: Arc<RwLock<SystemConfig>>,
    log_reload_handle: H,
) -> std::io::Result<()> {
    let path = match config.path {
        Some(path) => path,
        None => return Ok(()),
    };

    let peers_listener = create_unix_socket(&path)?;

    // this binary needs to run as root to be able to adjust the system clock.
    // by default, the socket inherits root permissions, but the client should not need
    // elevated permissions to read from the socket. So we explicitly set the permissions
    let permissions: std::fs::Permissions = PermissionsExt::from_mode(config.mode);
    std::fs::set_permissions(&path, permissions)?;

    let mut msg = Vec::with_capacity(16 * 1024);

    loop {
        let (mut stream, _addr) = peers_listener.accept().await?;

        let operation: ConfigUpdate = crate::sockets::read_json(&mut stream, &mut msg).await?;

        tracing::info!(?operation, "dynamic config update");

        if let Some(filter) = operation.log_filter {
            log_reload_handle.update_log(EnvFilter::new(filter));
        }

        let mut config = system_config.write().await;

        if let Some(panic_threshold) = operation.panic_threshold {
            config.panic_threshold = StepThreshold {
                forward: Some(NtpDuration::from_seconds(panic_threshold)),
                backward: Some(NtpDuration::from_seconds(panic_threshold)),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::sockets::write_json;

    use super::*;

    struct TestLogReloader {}
    impl LogReloader for TestLogReloader {
        fn update_log(&self, _f: EnvFilter) {}
    }

    #[tokio::test]
    async fn test_dynamic_configuration_change() {
        let system_config = Arc::new(RwLock::new(SystemConfig::default()));
        let system_config_test = system_config.clone();

        let path = std::env::temp_dir().join("ntp-test-stream-4");
        let config = ConfigureConfig {
            path: Some(path.clone()),
            mode: 0o700,
        };

        let handle = spawn(config, system_config, TestLogReloader {}).await;

        // Ensure client has started.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();

        write_json(
            &mut stream,
            &ConfigUpdate {
                log_filter: Some("info".into()),
                panic_threshold: Some(600.),
            },
        )
        .await
        .unwrap();

        // Ensure message is handled.
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            system_config_test.read().await.panic_threshold.forward,
            Some(NtpDuration::from_seconds(600.))
        );

        handle.abort();
    }
}
