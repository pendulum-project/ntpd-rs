use std::{
    fs::{File, OpenOptions},
    os::unix::prelude::{OpenOptionsExt, PermissionsExt},
    sync::Arc,
};

use ntp_proto::{KeySet, KeySetProvider};
use tokio::sync::watch;
use tracing::{instrument, warn, Span};

use super::config::KeysetConfig;

#[instrument(level = tracing::Level::ERROR, name = "KeySet Provider", skip_all, fields(path = debug(config.key_storage_path.clone())))]
pub async fn spawn(config: KeysetConfig) -> watch::Receiver<Arc<KeySet>> {
    let (mut provider, mut next_interval) = match &config.key_storage_path {
        Some(path) => {
            let path = path.to_owned();

            if let Ok(meta) = std::fs::metadata(&path) {
                let perm = meta.permissions();

                #[allow(clippy::cast_possible_truncation)]
                if perm.mode() as libc::mode_t & (libc::S_IWOTH | libc::S_IROTH | libc::S_IXOTH)
                    != 0
                {
                    warn!("Keyset file permissions: Others can interact with it. This is a potential security issue.");
                }
            }

            let (provider, time) = tokio::task::spawn_blocking(
                move || -> std::io::Result<(KeySetProvider, std::time::SystemTime)> {
                    let mut input = File::open(path)?;
                    KeySetProvider::load(&mut input, config.stale_key_count)
                },
            )
            .await
            .unwrap_or_else(|e| Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            .unwrap_or_else(|e| {
                warn!(error = ?e, "Could not load nts server keys, starting with new set");
                (
                    KeySetProvider::new(config.stale_key_count),
                    std::time::SystemTime::now(),
                )
            });
            (
                provider,
                std::time::Duration::from_secs(config.key_rotation_interval as _).saturating_sub(
                    std::time::SystemTime::now()
                        .duration_since(time)
                        .unwrap_or(std::time::Duration::from_secs(0)),
                ),
            )
        }
        None => (
            KeySetProvider::new(config.stale_key_count),
            std::time::Duration::from_secs(config.key_rotation_interval as _),
        ),
    };
    let (tx, rx) = watch::channel(provider.get());
    let span = Span::current();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        loop {
            // First save, then sleep. Ensures new sets created at boot are also saved.
            if let Some(path) = &config.key_storage_path {
                if let Err(e) = (|| -> std::io::Result<()> {
                    let mut output = OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .mode(0o600)
                        .open(path)?;
                    provider.store(&mut output)
                })() {
                    if e.kind() == std::io::ErrorKind::NotFound
                        || e.kind() == std::io::ErrorKind::PermissionDenied
                    {
                        warn!(error = ?e, "Could not store nts server keys, parent directory does not exist or has insufficient permissions");
                    } else {
                        warn!(error = ?e, "Could not store nts server keys");
                    }
                }
            }
            if tx.send(provider.get()).is_err() {
                break;
            }
            std::thread::sleep(next_interval);
            next_interval = std::time::Duration::from_secs(config.key_rotation_interval as _);
            provider.rotate();
        }
    });
    rx
}
