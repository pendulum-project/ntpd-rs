#![no_main]
use libfuzzer_sys::{
    arbitrary::{
        size_hint::{and, or},
        Arbitrary,
    },
    fuzz_target,
};
use ntp_daemon::{config::subnet::IpSubnet, fuzz_ipfilter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ASubnet(IpSubnet);

impl<'a> Arbitrary<'a> for ASubnet {
    fn arbitrary(
        u: &mut libfuzzer_sys::arbitrary::Unstructured<'a>,
    ) -> libfuzzer_sys::arbitrary::Result<Self> {
        let ipv4: bool = u.arbitrary()?;
        if ipv4 {
            let mask: u8 = u.int_in_range(0..=32)?;
            let addr = IpAddr::V4(Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?));
            Ok(ASubnet(IpSubnet { mask, addr }))
        } else {
            let mask: u8 = u.int_in_range(0..=128)?;
            let addr = IpAddr::V6(Ipv6Addr::from(u.arbitrary::<[u8; 16]>()?));
            Ok(ASubnet(IpSubnet { mask, addr }))
        }
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        and(
            <bool as Arbitrary<'a>>::size_hint(depth),
            or(
                <[u8; 4] as Arbitrary<'a>>::size_hint(depth),
                <[u8; 16] as Arbitrary<'a>>::size_hint(depth),
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AIp(IpAddr);

impl<'a> Arbitrary<'a> for AIp {
    fn arbitrary(
        u: &mut libfuzzer_sys::arbitrary::Unstructured<'a>,
    ) -> libfuzzer_sys::arbitrary::Result<Self> {
        let ipv4: bool = u.arbitrary()?;
        if ipv4 {
            Ok(AIp(IpAddr::V4(Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?))))
        } else {
            Ok(AIp(IpAddr::V6(Ipv6Addr::from(u.arbitrary::<[u8; 16]>()?))))
        }
    }
}

fuzz_target!(|spec: (Vec<ASubnet>, Vec<AIp>)| {
    let subnets: Vec<_> = spec.0.into_iter().map(|v| v.0).collect();
    let addrs: Vec<_> = spec.1.into_iter().map(|v| v.0).collect();
    fuzz_ipfilter(&subnets, &addrs);
});
