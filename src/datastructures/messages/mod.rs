use num_enum::{IntoPrimitive, TryFromPrimitive};

mod announce;
mod control_field;
mod delay_req;
mod delay_resp;
mod flag_field;
mod follow_up;
mod header;
mod sync;

pub use announce::*;
pub use control_field::*;
pub use delay_req::*;
pub use delay_resp::*;
pub use flag_field::*;
pub use follow_up::*;
pub use header::*;
pub use sync::*;

#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PDelayReq = 0x2,
    PDelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PDelayRespFollowUp = 0xA,
    Announce = 0xB,
    Signaling = 0xC,
    Management = 0xD,
}
