#![no_main]

use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use libfuzzer_sys::fuzz_target;
use ntp_proto::{KeyExchangeRequest, NtsError};

fn parse(data: &[u8]) -> Result<KeyExchangeRequest<'static>, NtsError> {
    let Poll::Ready(result) =
        pin!(KeyExchangeRequest::parse(data)).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("Future stalled unexpectedly.");
    };

    result
}

fn serialize(request: KeyExchangeRequest, buf: &mut Vec<u8>) -> Result<(), std::io::Error> {
    let Poll::Ready(result) =
        pin!(request.serialize(buf)).poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("Future stalled unexpectedly.");
    };

    result
}

fuzz_target!(|data: Vec<u8>| {
    if let Ok(request) = parse(&data) {
        let mut a = vec![];
        serialize(request, &mut a).unwrap();
        let request2 = parse(&a).unwrap();
        let mut b = vec![];
        serialize(request2, &mut b).unwrap();
        assert_eq!(a, b);
    }
});
