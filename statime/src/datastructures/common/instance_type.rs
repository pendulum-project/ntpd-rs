#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum InstanceType {
    OrdinaryClock = 0x00,
    BoundaryClock = 0x01,
    P2PTransparentClock = 0x02,
    E2ETransparentClock = 0x03,
}
