use std::{
    fs::{File, OpenOptions},
    os::unix::prelude::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};

use ntp_proto::{KeySet, KeySetProvider};
use tokio::sync::watch;
use tracing::warn;

use super::config::KeysetConfig;

/// Reads the file metadata and checks if the permissions are as expected. Logs a warning if they are not.
fn permission_check(path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };

    if meta.permissions().mode() as libc::mode_t & (libc::S_IWOTH | libc::S_IROTH | libc::S_IXOTH)
        != 0
    {
        warn!("Keyset file permissions: Others can interact with it. This is a potential security issue.");
    }
}

fn run(
    mut provider: KeySetProvider,
    config: KeysetConfig,
    mut next_interval: Duration,
    tx: watch::Sender<Arc<KeySet>>,
) {
    loop {
        std::thread::sleep(next_interval);
        next_interval = std::time::Duration::from_secs(config.key_rotation_interval as _);
        provider.rotate();
        if let Some(path) = &config.key_storage_path {
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .and_then(|mut output| provider.store(&mut output))
                .unwrap_or_else(|error| {
                    warn!(?error, "Could not store nts server keys");
                });
        }
        if tx.send(provider.get()).is_err() {
            break;
        }
    }
}

pub fn spawn(config: KeysetConfig) -> watch::Receiver<Arc<KeySet>> {
    let (provider, next_interval) = config
        .key_storage_path
        .as_ref()
        .and_then(|path| {
            let path: &Path = path.as_ref();

            permission_check(path);

            File::open(path).map_or_else(
                |error| {
                    warn!(
                        ?error,
                        "Could not read nts server keys file, starting with new set"
                    );
                    None
                },
                Some,
            )
        })
        .and_then(|mut input| {
            KeySetProvider::load(&mut input, config.stale_key_count).map_or_else(
                |error| {
                    warn!(
                        ?error,
                        "Could not load nts server keys, starting with new set"
                    );
                    None
                },
                |(provider, time)| {
                    let next_interval =
                        std::time::Duration::from_secs(config.key_rotation_interval as _)
                            .saturating_sub(
                                std::time::SystemTime::now()
                                    .duration_since(time)
                                    .unwrap_or_default(),
                            );
                    Some((provider, next_interval))
                },
            )
        })
        .unwrap_or_else(|| {
            (
                KeySetProvider::new(config.stale_key_count),
                std::time::Duration::from_secs(config.key_rotation_interval as _),
            )
        });

    let (tx, rx) = watch::channel(provider.get());
    std::thread::spawn(move || run(provider, config, next_interval, tx));
    rx
}
