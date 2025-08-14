#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::NtsRecord;
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

fn parse(data: &[u8]) -> Result<NtsRecord<'_>, std::io::Error> {
    let Poll::Ready(result) =
        pin!(NtsRecord::parse(data)).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("Future stalled unexpectedly.");
    };

    result
}

fn serialize(request: NtsRecord, buf: &mut Vec<u8>) -> Result<(), std::io::Error> {
    let Poll::Ready(result) =
        pin!(request.serialize(buf)).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("Future stalled unexpectedly.");
    };

    result
}

fuzz_target!(|data: Vec<u8>| {
    if let Ok(record) = parse(&data) {
        let mut a = vec![];
        serialize(record.clone(), &mut a).unwrap();
        let record2 = parse(&a).unwrap();
        assert_eq!(record, record2);
        let mut b = vec![];
        serialize(record2, &mut b).unwrap();
        assert_eq!(a, b);
    }
});
