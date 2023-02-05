#![cfg(feature = "std")]

use std::borrow::ToOwned;

use fixed::traits::ToFixed;

use crate::datastructures::common::{ClockIdentity, TimeSource};
use crate::datastructures::datasets::{DelayMechanism, PortDS, TimePropertiesDS};
use crate::network::test::TestRuntimePort;
use crate::{
    bmc::bmca::Bmca,
    datastructures::{
        common::{ClockQuality, PortIdentity, TimeInterval, Timestamp},
        messages::MessageBuilder,
    },
    network::{test::TestRuntime, NetworkRuntime},
    port::Measurement,
    time::{Duration, Instant},
};

use super::{SequenceIdGenerator, SlaveState};

fn test_port_data(network_runtime: &mut TestRuntime) -> PortData<TestRuntimePort> {
    let tc_port = network_runtime.open("".to_owned(), true).unwrap();
    let nc_port = network_runtime.open("".to_owned(), false).unwrap();

    let identity = PortIdentity {
        clock_identity: ClockIdentity([1, 0, 0, 0, 0, 0, 0, 0]),
        port_number: 0,
    };

    let port_ds = PortDS::new(identity, 37, 1, 5, 1, DelayMechanism::E2E, 37, 0, 1);

    PortData {
        tc_port,
        nc_port,
        delay_req_ids: SequenceIdGenerator::default(),
        sdo: 0,
        domain: 0,
        port_ds,
        bmca: Bmca::new(TimeInterval(2_000_000_000u64.to_fixed()), identity),
        clock_quality: ClockQuality::default(),
        time_properties: TimePropertiesDS::new_arbitrary(
            false,
            false,
            TimeSource::InternalOscillator,
        ),
        announce_seq_id: 0,
        delay_resp_seq_id: 0,
        follow_up_seq_id: 0,
        sync_seq_id: 0,
    }
}

#[test]
fn test_measurement_flow() {
    let mut network_runtime = TestRuntime::default();

    let master_id = PortIdentity::default();

    let mut test_state = SlaveState {
        remote_master: master_id,
        ..Default::default()
    };

    let mut test_port_data = test_port_data(&mut network_runtime);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .sync_message(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
        Some(Instant::from_nanos(5)),
    );

    assert_eq!(test_state.extract_measurement(), None);

    let delay_req = network_runtime.get_sent().unwrap();
    test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

    assert_eq!(test_state.extract_measurement(), None);

    let requesting_port_identity = test_port_data.port_ds.port_identity;
    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((2 as i16).to_fixed()))
            .delay_resp_message(
                Timestamp {
                    seconds: 0,
                    nanos: 11,
                },
                requesting_port_identity,
            ),
        None,
    );

    assert_eq!(
        test_state.extract_measurement(),
        Some(Measurement {
            master_offset: Duration::from_nanos(1),
            event_time: Instant::from_nanos(5),
        })
    );
}

#[test]
fn test_measurement_flow_timestamps_out_of_order() {
    let mut network_runtime = TestRuntime::default();

    let master_id = PortIdentity::default();
    let mut test_id = PortIdentity::default();
    test_id.clock_identity.0[0] += 1;

    let mut test_state = SlaveState {
        remote_master: master_id,
        ..Default::default()
    };

    let mut test_port_data = test_port_data(&mut network_runtime);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .sync_message(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
        Some(Instant::from_nanos(5)),
    );

    assert_eq!(test_state.extract_measurement(), None);

    let delay_req = network_runtime.get_sent().unwrap();

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((2 as i16).to_fixed()))
            .delay_resp_message(
                Timestamp {
                    seconds: 0,
                    nanos: 11,
                },
                test_id,
            ),
        None,
    );

    assert_eq!(test_state.extract_measurement(), None);

    test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

    assert_eq!(
        test_state.extract_measurement(),
        Some(Measurement {
            master_offset: Duration::from_nanos(1),
            event_time: Instant::from_nanos(5),
        })
    );
}

#[test]
fn test_measurement_flow_followup() {
    let mut network_runtime = TestRuntime::default();

    let master_id = PortIdentity::default();
    let mut test_id = PortIdentity::default();
    test_id.clock_identity.0[0] += 1;

    let mut test_state = SlaveState {
        remote_master: master_id,
        ..Default::default()
    };

    let mut test_port_data = test_port_data(&mut network_runtime);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .two_step_flag(true)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .sync_message(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
        Some(Instant::from_nanos(5)),
    );

    assert_eq!(test_state.extract_measurement(), None);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .two_step_flag(true)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .follow_up_message(Timestamp {
                seconds: 0,
                nanos: 1,
            }),
        None,
    );

    assert_eq!(test_state.extract_measurement(), None);

    let delay_req = network_runtime.get_sent().unwrap();
    test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

    assert_eq!(test_state.extract_measurement(), None);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((2 as i16).to_fixed()))
            .delay_resp_message(
                Timestamp {
                    seconds: 0,
                    nanos: 11,
                },
                test_id,
            ),
        None,
    );

    assert_eq!(
        test_state.extract_measurement(),
        Some(Measurement {
            master_offset: Duration::from_nanos(0),
            event_time: Instant::from_nanos(5),
        })
    );
}

#[test]
fn test_measurement_flow_followup_out_of_order() {
    let mut network_runtime = TestRuntime::default();

    let master_id = PortIdentity::default();
    let mut test_id = PortIdentity::default();
    test_id.clock_identity.0[0] += 1;

    let mut test_state = SlaveState {
        remote_master: master_id,
        ..Default::default()
    };

    let mut test_port_data = test_port_data(&mut network_runtime);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .two_step_flag(true)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .follow_up_message(Timestamp {
                seconds: 0,
                nanos: 1,
            }),
        None,
    );

    assert_eq!(test_state.extract_measurement(), None);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .two_step_flag(true)
            .correction_field(TimeInterval((1 as i16).to_fixed()))
            .sync_message(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
        Some(Instant::from_nanos(5)),
    );

    assert_eq!(test_state.extract_measurement(), None);

    let delay_req = network_runtime.get_sent().unwrap();
    test_state.handle_send_timestamp(delay_req.index, Instant::from_nanos(7));

    assert_eq!(test_state.extract_measurement(), None);

    test_state.handle_message(
        &mut test_port_data,
        MessageBuilder::new()
            .sdo_id(0)
            .unwrap()
            .domain_number(0)
            .correction_field(TimeInterval((2 as i16).to_fixed()))
            .delay_resp_message(
                Timestamp {
                    seconds: 0,
                    nanos: 11,
                },
                test_id,
            ),
        None,
    );

    assert_eq!(
        test_state.extract_measurement(),
        Some(Measurement {
            master_offset: Duration::from_nanos(0),
            event_time: Instant::from_nanos(5),
        })
    );
}
