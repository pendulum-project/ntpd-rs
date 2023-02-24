use std::net::SocketAddr;

use super::{
    BasicSpawner, PeerCreateParameters, PeerId, PeerRemovedEvent, SpawnAction, SpawnEvent,
    SpawnerId,
};
use tokio::sync::mpsc;

pub struct DummySpawner {
    id: SpawnerId,
    peer_ids: Vec<PeerId>,
    to_spawn: Vec<PeerCreateParameters>,
    to_activate: isize,
}

#[derive(Debug, thiserror::Error)]
pub enum DummySpawnerError {}

impl DummySpawner {
    pub fn new(to_spawn: Vec<PeerCreateParameters>, keep_active: usize) -> DummySpawner {
        DummySpawner {
            id: SpawnerId::new(),
            peer_ids: to_spawn.iter().map(|p| p.id).collect(),
            to_spawn,
            to_activate: keep_active as isize,
        }
    }

    pub fn peer_ids(&self) -> impl Iterator<Item = PeerId> {
        self.peer_ids.clone().into_iter()
    }

    pub fn simple(addr: Vec<SocketAddr>, keep_active: usize) -> DummySpawner {
        let to_spawn = addr
            .into_iter()
            .map(PeerCreateParameters::from_addr)
            .collect();
        Self::new(to_spawn, keep_active)
    }

    pub fn one_simple(addr: SocketAddr) -> DummySpawner {
        Self::simple(vec![addr], 1)
    }

    pub fn empty() -> DummySpawner {
        Self::simple(vec![], 0)
    }

    async fn spawn(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), DummySpawnerError> {
        while self.to_activate > 0 {
            if self.to_spawn.is_empty() {
                return Ok(());
            } else {
                let first = self.to_spawn.remove(0);
                action_tx
                    .send(SpawnEvent {
                        id: self.id,
                        action: SpawnAction::Create(first),
                    })
                    .await
                    .expect("Channel was closed unexpectedly");
                self.to_activate -= 1;
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl BasicSpawner for DummySpawner {
    type Error = DummySpawnerError;

    async fn handle_init(
        &mut self,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), DummySpawnerError> {
        self.spawn(action_tx).await
    }

    async fn handle_peer_removed(
        &mut self,
        _removed_peer: PeerRemovedEvent,
        action_tx: &mpsc::Sender<SpawnEvent>,
    ) -> Result<(), DummySpawnerError> {
        self.spawn(action_tx).await
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        "dummy".into()
    }
}
