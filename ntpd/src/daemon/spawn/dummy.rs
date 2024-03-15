use std::net::SocketAddr;

use super::{
    BasicSpawner, PeerCreateParameters, PeerRemovedEvent, SpawnAction, SpawnEvent, SpawnerId,
};
use tokio::sync::mpsc;

pub struct DummySpawner {
    id: SpawnerId,
    to_spawn: Vec<PeerCreateParameters>,
    to_activate: isize,
}

#[derive(Debug, thiserror::Error)]
pub enum DummySpawnerError {}

impl DummySpawner {
    pub fn new(to_spawn: Vec<PeerCreateParameters>, keep_active: usize) -> DummySpawner {
        DummySpawner {
            id: SpawnerId::new(),
            to_spawn,
            to_activate: keep_active as isize,
        }
    }

    pub fn simple(addr: Vec<SocketAddr>, keep_active: usize) -> DummySpawner {
        let to_spawn = addr
            .into_iter()
            .map(PeerCreateParameters::from_new_addr)
            .collect();
        Self::new(to_spawn, keep_active)
    }

    pub fn empty() -> DummySpawner {
        Self::simple(vec![], 0)
    }
}

#[async_trait::async_trait]
impl BasicSpawner for DummySpawner {
    type Error = DummySpawnerError;

    async fn try_spawn(&mut self, action_tx: &mpsc::Sender<SpawnEvent>) -> Result<(), Self::Error> {
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

    fn is_complete(&self) -> bool {
        self.to_activate == 0
    }

    async fn handle_peer_removed(
        &mut self,
        _removed_peer: PeerRemovedEvent,
    ) -> Result<(), DummySpawnerError> {
        Ok(())
    }

    fn get_id(&self) -> SpawnerId {
        self.id
    }

    fn get_addr_description(&self) -> String {
        "dummy".into()
    }

    fn get_description(&self) -> &str {
        "dummy"
    }
}
