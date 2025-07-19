use std::fmt::Display;
use std::{net::SocketAddr, ops::Deref};

use ntp_proto::SourceConfig;
use tokio::sync::mpsc;
use tracing::warn;

use crate::daemon::config::CsptpSourceConfig;
use crate::daemon::spawn::{
    CsptpSourceCreateParameters, SourceCreateParameters, SourceId, SourceRemovalReason,
    SourceRemovedEvent, SpawnAction, SpawnEvent, Spawner, SpawnerId,
};

pub struct CsptpSpawner {
    id: SpawnerId,
    config: CsptpSourceConfig,
    source_config: SourceConfig,
    resolved: Option<SocketAddr>,
    has_spawned: bool,
}

#[derive(Debug)]
pub enum CsptpSpawnError {
    SendError(mpsc::error::SendError<SpawnEvent>),
}

impl Display for CsptpSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "Channel send error: {e}"),
        }
    }
}

impl From<mpsc::error::SendError<SpawnEvent>> for CsptpSpawnError {
    fn from(value: mpsc::error::SendError<SpawnEvent>) -> Self {
        Self::SendError(value)
    }
}

impl std::error::Error for CsptpSpawnError {}

impl CsptpSpawner {
    pub fn new(config: CsptpSourceConfig, source_config: SourceConfig) -> Self {
        Self {
            id: Default::default(),
            config,
            source_config,
            resolved: None,
            has_spawned: false,
        }
    }

    async fn do_resolve(&mut self, force_resolve: bool) -> Option<SocketAddr> {
        if let (false, Some(addr)) = (force_resolve, self.resolved) {
            Some(addr)
        } else {
            match self.config.address.lookup_host().await {
                Ok(mut addresses) => match addresses.next() {
                    None => {
                        warn!("Could not resolve source address, retrying");
                        None
                    }
                    Some(first) => {
                        self.resolved = Some(first);
                        self.resolved
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "error while resolving source address, retrying");
                    None
                }
            }
        }
    }
}

impl Spawner for CsptpSpawner {
    type Error = CsptpSpawnError;

    async fn try_spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), CsptpSpawnError> {
        let Some(addr) = self.do_resolve(false).await else {
            return Ok(());
        };
        action_tx
            .send(SpawnEvent::new(
                self.id,
                SpawnAction::Create(SourceCreateParameters::Csptp(CsptpSourceCreateParameters {
                    id: SourceId::new(),
                    addr,
                    normalized_addr: self.config.address.deref().clone(),
                    config: self.source_config.clone(),
                    nts: None,
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
    ) -> Result<(), CsptpSpawnError> {
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
        self.config.address.to_string()
    }

    fn get_description(&self) -> &str {
        "csptp"
    }
}
