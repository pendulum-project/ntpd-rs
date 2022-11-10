#![no_main]
use libfuzzer_sys::{
    arbitrary::{
        size_hint::{and, or},
        Arbitrary,
    },
    fuzz_target,
};
use ntp_daemon::{config::subnet::IpSubnet, fuzz_ipfilter};
use ntp_proto::Record;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|record: Record| {
    let mut buffer = Cursor::new([0u8; 4096]);
    record.write(&mut buffer).unwrap();

    buffer.set_position(0);
    Record::read(&mut buffer).unwrap();
});
