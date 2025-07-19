use std::net::SocketAddr;

use ntp_proto::{NtpClock, NtpDuration, SourceController, TwoWaySource};
use timestamped_socket::{
    interface::InterfaceName,
    socket::{Connected, Socket},
};
use tracing::{Instrument, Span, instrument};

use crate::daemon::{config::TimestampMode, ntp_source::SourceChannels, spawn::SourceId};

pub(crate) struct CsptpSourceTask<
    C: 'static + NtpClock + Send,
    Controller: SourceController<MeasurementDelay = NtpDuration>,
> {
    index: SourceId,
    clock: C,
    interface: Option<InterfaceName>,
    timestamp_mode: TimestampMode,
    name: String,
    source_addr: SocketAddr,
    socket: Option<Socket<SocketAddr, Connected>>,
    channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,

    source: TwoWaySource<Controller>,
}

impl<C: 'static + NtpClock + Send, Controller: SourceController<MeasurementDelay = NtpDuration>>
    CsptpSourceTask<C, Controller>
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(level = tracing::Level::ERROR, name = "CSPTP Source", skip(timestamp_mode, clock, channels, source))]
    pub fn spawn(
        index: SourceId,
        name: String,
        source_addr: SocketAddr,
        interface: Option<InterfaceName>,
        clock: C,
        timestamp_mode: TimestampMode,
        channels: SourceChannels<Controller::ControllerMessage, Controller::SourceMessage>,
        source: TwoWaySource<Controller>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            (async move {
                let mut process = CsptpSourceTask {
                    index,
                    name,
                    clock,
                    channels,
                    interface,
                    timestamp_mode,
                    source_addr,
                    socket: None,
                    source,
                };
            })
            .instrument(Span::current()),
        )
    }
}
