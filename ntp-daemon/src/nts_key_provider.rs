use std::sync::Arc;

use ntp_proto::{KeySet, KeySetProvider};
use tokio::sync::watch;

use crate::config::KeysetConfig;

pub fn spawn(config: KeysetConfig) -> watch::Receiver<Arc<KeySet>> {
    let mut provider = KeySetProvider::new(config.old_keys);
    let (tx, rx) = watch::channel(provider.get());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(
                config.rotation_interval as _,
            ))
            .await;
            provider.rotate();
            if tx.send(provider.get()).is_err() {
                break;
            }
        }
    });
    rx
}
