use std::convert::Infallible;

use arrayvec::{ArrayVec, CapacityError};
use fixed::traits::ToFixed;

use crate::datastructures::common::{ClockIdentity, PortIdentity, TimeInterval, Timestamp};
use crate::datastructures::messages::{MessageBuilder, SdoId, MAX_DATA_LEN};
use crate::network::{NetworkPacket, NetworkPort, NetworkRuntime};
use crate::port::state::SlaveState;
use crate::port::Measurement;
use crate::time::{Duration, Instant};

#[derive(Debug)]
pub struct TestRuntime {
    pub data_sender: tokio::sync::broadcast::Sender<TestNetworkPacket>,
}

impl NetworkRuntime for TestRuntime {
    type InterfaceDescriptor = ();
    type NetworkPort = TestNetworkPort;
    type Error = Infallible;

    async fn open(
        &mut self,
        _interface: Self::InterfaceDescriptor,
    ) -> Result<Self::NetworkPort, Self::Error> {
        Ok(TestNetworkPort {
            data_sender: self.data_sender.clone(),
            data_receiver: self.data_sender.subscribe(),
        })
    }
}

impl Default for TestRuntime {
    fn default() -> Self {
        Self {
            data_sender: tokio::sync::broadcast::channel(100).0,
        }
    }
}

#[derive(Debug)]
pub struct TestNetworkPort {
    data_sender: tokio::sync::broadcast::Sender<TestNetworkPacket>,
    data_receiver: tokio::sync::broadcast::Receiver<TestNetworkPacket>,
}

impl NetworkPort for TestNetworkPort {
    type Error = CapacityError;

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.data_sender
            .send(TestNetworkPacket {
                data: data.try_into()?,
            })
            .unwrap();

        Ok(())
    }

    async fn send_time_critical(&mut self, data: &[u8]) -> Result<Instant, Self::Error> {
        self.data_sender
            .send(TestNetworkPacket {
                data: data.try_into()?,
            })
            .unwrap();

        Ok(Instant::from_nanos(7))
    }

    async fn recv(&mut self) -> Result<NetworkPacket, Self::Error> {
        Ok(NetworkPacket {
            data: self.data_receiver.recv().await.unwrap().data,
            timestamp: Instant::from_secs(0),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestNetworkPacket {
    data: ArrayVec<u8, MAX_DATA_LEN>,
}

#[tokio::test]
async fn test_measurement_flow() {
    let mut network_runtime = TestRuntime::default();

    let mut network_port = network_runtime.open(()).await.unwrap();

    let port_identity = PortIdentity {
        clock_identity: ClockIdentity([1, 0, 0, 0, 0, 0, 0, 0]),
        port_number: 0,
    };

    let remote_master = PortIdentity::default();

    let mut test_state = SlaveState::new(remote_master);

    assert_eq!(test_state.extract_measurement(), None);

    let sync_message = MessageBuilder::new()
        .sdo_id(SdoId::default())
        .domain_number(0)
        .correction_field(TimeInterval((1i16).to_fixed()))
        .sync_message(Timestamp {
            seconds: 0,
            nanos: 0,
        });

    test_state
        .handle_message(
            sync_message,
            Instant::from_nanos(5),
            &mut network_port,
            port_identity,
        )
        .await
        .unwrap();

    assert_eq!(test_state.extract_measurement(), None);

    let delay_resp_message = MessageBuilder::new()
        .sdo_id(SdoId::default())
        .domain_number(0)
        .correction_field(TimeInterval((2i16).to_fixed()))
        .delay_resp_message(
            Timestamp {
                seconds: 0,
                nanos: 11,
            },
            port_identity,
        );

    test_state
        .handle_message(
            delay_resp_message,
            Instant::from_nanos(13),
            &mut network_port,
            port_identity,
        )
        .await
        .unwrap();

    assert_eq!(
        test_state.extract_measurement(),
        Some(Measurement {
            master_offset: Duration::from_nanos(1),
            event_time: Instant::from_nanos(5),
        })
    );
}
