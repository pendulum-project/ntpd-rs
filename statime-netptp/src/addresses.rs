use std::{
    io::Result,
    task::{Context, Poll},
};

use timestamped_socket::{
    interface::InterfaceName,
    socket::{FullTimestampData, SendTimestampToken},
};

mod ipv4;
mod ipv6;

/// An address type which can be used for PTP/CSPTP traffic.
#[expect(private_bounds)]
pub trait PtpAddressFamily: SealedPtpAddressFamily + Copy + Eq + 'static {}

pub(crate) trait SealedPtpAddressFamily {
    type BoundInterface: BoundInterface<Addr = Self>;
}

pub(crate) trait BoundInterface: Sized + Sync + Send {
    type Addr;

    fn open(interface: Option<InterfaceName>, hardware_clock: Option<u32>) -> Result<Self>;

    fn poll_send_event(
        &self,
        buf: &[u8],
        from: Option<Self::Addr>,
        to: Self::Addr,
        cx: &mut Context,
    ) -> Poll<Result<SendTimestampToken>>;
    fn poll_send_general(
        &self,
        buf: &[u8],
        from: Option<Self::Addr>,
        to: Self::Addr,
        cx: &mut Context,
    ) -> Poll<Result<()>>;
    fn poll_recv(
        &self,
        buf: &mut [u8],
        cx: &mut Context,
    ) -> Poll<Result<timestamped_socket::socket::RecvResult<Self::Addr>>>;
    fn poll_recv_timestamp(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(SendTimestampToken, FullTimestampData)>>;
}
