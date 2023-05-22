#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum InstanceType {
    OrdinaryClock = 0x00,
    BoundaryClock = 0x01,
    #[allow(unused)]
    P2PTransparentClock = 0x02,
    #[allow(unused)]
    E2ETransparentClock = 0x03,
}
