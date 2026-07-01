use std::fmt::Display;
use std::net::IpAddr;

use tokio::sync::mpsc;

use crate::daemon::config::{CsptpSourceConfig, NormalizedAddress, NtpAddress};
use crate::daemon::spawn::{
    CsptpSourceCreateParameters, SourceCreateParameters, resolve_single_ntp_server,
};

use super::{
    ClockId, SourceRemovalReason, SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct CsptpSpawner {
    id: SpawnerId,
    config: CsptpSourceConfig,
    resolved: Option<IpAddr>,
    has_spawned: bool,
}

#[derive(Debug)]
pub enum CsptpSpawnerError {
    SendError(mpsc::error::SendError<SpawnEvent>),
}

impl Display for CsptpSpawnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "Channel send error: {e}"),
        }
    }
}

impl From<mpsc::error::SendError<SpawnEvent>> for CsptpSpawnerError {
    fn from(value: mpsc::error::SendError<SpawnEvent>) -> Self {
        Self::SendError(value)
    }
}

impl std::error::Error for CsptpSpawnerError {}

impl CsptpSpawner {
    pub fn new(config: CsptpSourceConfig) -> CsptpSpawner {
        CsptpSpawner {
            id: SpawnerId::new(),
            config,
            resolved: None,
            has_spawned: false,
        }
    }

    async fn do_resolve(&mut self, force_resolve: bool) -> Option<IpAddr> {
        if let (false, Some(addr)) = (force_resolve, self.resolved) {
            Some(addr)
        } else {
            let address = resolve_single_ntp_server(NtpAddress(NormalizedAddress::new_from_parts(
                &self.config.address,
                319,
            )))
            .await?;
            self.resolved = Some(address.ip());
            self.resolved
        }
    }
}

impl Spawner for CsptpSpawner {
    type Error = CsptpSpawnerError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), CsptpSpawnerError> {
        let Some(addr) = self.do_resolve(false).await else {
            return Ok(());
        };
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::Create(SourceCreateParameters::Csptp(CsptpSourceCreateParameters {
                    id: ClockId::new(),
                    addr,
                    config: self.config.clone(),
                })),
            ))
            .await?;
        self.has_spawned = true;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_spawned
    }

    async fn handle_source_removed(
        &mut self,
        removed_source: SourceRemovedEvent,
    ) -> Result<(), CsptpSpawnerError> {
        if removed_source.reason == SourceRemovalReason::Unreachable {
            // force new resolution
            self.resolved = None;
        }
        if removed_source.reason != SourceRemovalReason::Demobilized {
            self.has_spawned = false;
        }
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        self.config.address.clone()
    }

    fn get_description(&self) -> &'static str {
        "standard"
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::{self, error::TryRecvError};

    use crate::daemon::config::CsptpSourceConfig;
    use crate::daemon::spawn::{CsptpSourceCreateParameters, SourceCreateParameters, SpawnEvent};
    use crate::daemon::{
        spawn::{
            SourceRemovalReason, SourceRemovedEvent, SpawnAction, Spawner, csptp::CsptpSpawner,
        },
        system::MESSAGE_BUFFER_SIZE,
    };

    pub fn get_csptp_create_params(res: SpawnEvent) -> Option<CsptpSourceCreateParameters> {
        let SpawnAction::Create(SourceCreateParameters::Csptp(params)) = res.action else {
            return None;
        };
        Some(params)
    }

    #[tokio::test]
    async fn creates_a_source() {
        let mut spawner = CsptpSpawner::new(CsptpSourceConfig {
            address: "localhost".into(),
            domain: 128,
            poll_interval: Duration::from_secs(8),
            response_interval: Duration::from_secs(5),
        });
        let spawner_id = spawner.get_id();
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        assert_eq!(res.id, spawner_id);
        let SpawnAction::Create(create_params) = &res.action;
        assert_eq!(create_params.get_addr(), "::1");
        let params = get_csptp_create_params(res).unwrap();
        assert_eq!(params.addr.to_string(), "::1");

        // Should be complete after spawning
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn recreates_a_source() {
        let mut spawner = CsptpSpawner::new(CsptpSourceConfig {
            address: "localhost".into(),
            domain: 128,
            poll_interval: Duration::from_secs(8),
            response_interval: Duration::from_secs(5),
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_csptp_create_params(res).unwrap();
        assert!(spawner.is_complete());

        spawner
            .handle_source_removed(SourceRemovedEvent {
                id: params.id,
                reason: SourceRemovalReason::NetworkIssue,
            })
            .await
            .unwrap();

        assert!(!spawner.is_complete());
        spawner.try_spawn(&action_tx).await.unwrap();
        let res = action_rx.try_recv().unwrap();
        let params = get_csptp_create_params(res).unwrap();
        assert_eq!(params.addr.to_string(), "::1");
        assert!(spawner.is_complete());
    }

    #[tokio::test]
    async fn works_if_address_does_not_resolve() {
        let mut spawner = CsptpSpawner::new(CsptpSourceConfig {
            address: "does.not.resolve".into(),
            domain: 128,
            poll_interval: Duration::from_secs(8),
            response_interval: Duration::from_secs(5),
        });
        let (action_tx, mut action_rx) = mpsc::channel(MESSAGE_BUFFER_SIZE);

        spawner.try_spawn(&action_tx).await.unwrap();

        let res = action_rx.try_recv().unwrap_err();
        assert_eq!(res, TryRecvError::Empty);
    }
}
