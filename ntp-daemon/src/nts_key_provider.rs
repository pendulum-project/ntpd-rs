use std::{fs::File, sync::Arc};

use ntp_proto::{KeySet, KeySetProvider};
use tokio::sync::watch;
use tracing::{error, warn};

use crate::config::KeysetConfig;

pub async fn spawn(config: KeysetConfig) -> watch::Receiver<Arc<KeySet>> {
    let (mut provider, mut next_interval) = match &config.storage_path {
        Some(path) => {
            let path = path.to_owned();
            let (provider, time) = tokio::task::spawn_blocking(
                move || -> std::io::Result<(KeySetProvider, std::time::SystemTime)> {
                    let mut input = File::open(path)?;
                    KeySetProvider::load(&mut input, config.old_keys)
                },
            )
            .await
            .unwrap_or_else(|e| Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            .unwrap_or_else(|e| {
                error!(error = ?e, "Could not load nts server keys, starting with new set");
                (
                    KeySetProvider::new(config.old_keys),
                    std::time::SystemTime::now(),
                )
            });
            (
                provider,
                std::time::Duration::from_secs(config.rotation_interval as _).saturating_sub(
                    std::time::SystemTime::now()
                        .duration_since(time)
                        .unwrap_or(std::time::Duration::from_secs(0)),
                ),
            )
        }
        None => (
            KeySetProvider::new(config.old_keys),
            std::time::Duration::from_secs(config.rotation_interval as _),
        ),
    };
    let (tx, rx) = watch::channel(provider.get());
    tokio::task::spawn_blocking(move || loop {
        std::thread::sleep(next_interval);
        next_interval = std::time::Duration::from_secs(config.rotation_interval as _);
        provider.rotate();
        if let Some(path) = &config.storage_path {
            if let Err(e) = (|| -> std::io::Result<()> {
                let mut output = File::create(path)?;
                provider.store(&mut output)
            })() {
                warn!(error = ?e, "Could not store nts server keys");
            }
        }
        if tx.send(provider.get()).is_err() {
            break;
        }
    });
    rx
}
