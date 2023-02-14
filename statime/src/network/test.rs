#![cfg(feature = "std")]

use std::vec::Vec;

use crate::time::Instant;

use super::{NetworkPacket, NetworkPort, NetworkRuntime};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestNetworkPacket {
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct TestRuntime {
    pub data_sender: tokio::sync::broadcast::Sender<TestNetworkPacket>,
}

impl Default for TestRuntime {
    fn default() -> Self {
        Self {
            data_sender: tokio::sync::broadcast::channel(100).0,
        }
    }
}

#[derive(Debug)]
pub struct TestRuntimePort {
    data_sender: tokio::sync::broadcast::Sender<TestNetworkPacket>,
    data_receiver: tokio::sync::broadcast::Receiver<TestNetworkPacket>,
}

#[derive(Debug)]
pub enum TestError {}

impl NetworkRuntime for TestRuntime {
    type InterfaceDescriptor = ();
    type NetworkPort = TestRuntimePort;
    type Error = TestError;

    async fn open(
        &mut self,
        _interface: Self::InterfaceDescriptor,
    ) -> Result<Self::NetworkPort, Self::Error> {
        Ok(TestRuntimePort {
            data_sender: self.data_sender.clone(),
            data_receiver: self.data_sender.subscribe(),
        })
    }
}

impl NetworkPort for TestRuntimePort {
    type Error = TestError;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.data_sender
            .send(TestNetworkPacket {
                data: data.to_vec(),
            })
            .unwrap();
        Ok(())
    }

    async fn send_time_critical(
        &mut self,
        data: &[u8],
    ) -> Result<crate::time::Instant, Self::Error> {
        self.data_sender
            .send(TestNetworkPacket {
                data: data.to_vec(),
            })
            .unwrap();
        Ok(Instant::from_secs(0))
    }

    async fn recv(&mut self) -> Result<super::NetworkPacket, Self::Error> {
        Ok(NetworkPacket {
            data: self.data_receiver.recv().await.unwrap().data,
            timestamp: Instant::from_secs(0),
        })
    }
}
