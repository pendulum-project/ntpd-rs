#![no_main]
use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target,
};
use ntp_proto::fuzz_measurement_from_packet;

#[derive(Debug, Clone, Arbitrary)]
struct InputData {
    client: u64,
    client_interval: u32,
    server: u64,
    server_interval: u32,
    client_precision: i8,
    server_precision: i8,
}

fuzz_target!(|input: InputData| {
    fuzz_measurement_from_packet(
        input.client,
        input.client_interval,
        input.server,
        input.server_interval,
        input.client_precision,
        input.server_precision,
    );
});
