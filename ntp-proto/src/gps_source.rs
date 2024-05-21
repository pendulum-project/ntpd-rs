use crate::{
    cookiestash::CookieStash,
   
    packet::{Cipher, NtpLeapIndicator, RequestIdentifier},
    time_types::{NtpDuration, NtpInstant, NtpTimestamp} ,
};
use crate::source::Measurement;
use std::time::Duration;

use tracing::{info, instrument, warn};

pub struct SourceNtsData {
    pub(crate) cookies: CookieStash,
    // Note: we use Box<dyn Cipher> to support the use
    // of multiple different ciphers, that might differ
    // in the key information they need to keep.
    pub(crate) c2s: Box<dyn Cipher>,
    pub(crate) s2c: Box<dyn Cipher>,
}

#[cfg(any(test, feature = "__internal-test"))]
impl SourceNtsData {
    pub fn get_cookie(&mut self) -> Option<Vec<u8>> {
        self.cookies.get()
    }

    pub fn get_keys(self) -> (Box<dyn Cipher>, Box<dyn Cipher>) {
        (self.c2s, self.s2c)
    }
}

impl std::fmt::Debug for SourceNtsData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceNtsData")
            .field("cookies", &self.cookies)
            .finish()
    }
}

#[derive(Debug)]
pub struct GpsSource {


    // Identifier of the last request sent to the server. This is correlated
    // with any received response from the server to guard against replay
    // attacks and packet reordering.
    current_request_identifier: Option<(RequestIdentifier, NtpInstant)>,

}

// #[derive(Debug, Copy, Clone)]
// pub struct Measurement {
//     pub delay: NtpDuration,
//     pub offset: NtpDuration,
//     pub transmit_timestamp: NtpTimestamp,
//     pub receive_timestamp: NtpTimestamp,
//     pub localtime: NtpTimestamp,
//     pub monotime: NtpInstant,

//     pub stratum: u8,
//     pub root_delay: NtpDuration,
//     pub root_dispersion: NtpDuration,
//     pub leap: NtpLeapIndicator,
//     pub precision: i8,
// }

// impl Measurement {
//     fn from_packet(
//         send_timestamp: NtpTimestamp,
//         recv_timestamp: NtpTimestamp,
//         local_clock_time: NtpInstant,
//     ) -> Self {
//         Self {
//             delay: NtpDuration::default(),
//             offset: NtpDuration::default(),
//             transmit_timestamp: send_timestamp,
//             receive_timestamp: recv_timestamp,
//             localtime: send_timestamp + (recv_timestamp - send_timestamp) / 2,
//             monotime: local_clock_time,

//             stratum: 16,
//             root_delay: NtpDuration::default(),
//             root_dispersion: NtpDuration::default(),
//             leap: NtpLeapIndicator::NoWarning,
//             precision: 0,
//         }
//     }
// }



// #[derive(Debug, Clone, Copy)]
// pub struct GpsSourceSnapshot {
//     pub source_addr: SocketAddr,

//     pub source_id: ReferenceId,

//     pub poll_interval: PollInterval,

//     pub stratum: u8,
//     pub reference_id: ReferenceId,

//     pub protocol_version: ProtocolVersion,

//     #[cfg(feature = "ntpv5")]
//     pub bloom_filter: Option<BloomFilter>,
// }

// impl GpsSourceSnapshot {
//     pub fn accept_synchronization(
//         &self,
//         local_stratum: u8,
//         local_ips: &[IpAddr],
//         #[cfg_attr(not(feature = "ntpv5"), allow(unused_variables))] system: &SystemSnapshot,
//     ) -> Result<(), AcceptSynchronizationError> {
//         use AcceptSynchronizationError::*;

//         if self.stratum >= local_stratum {
//             info!(
//                 source_stratum = self.stratum,
//                 own_stratum = local_stratum,
//                 "Source rejected due to invalid stratum. The stratum of a source must be lower than the own stratum",
//             );
//             return Err(Stratum);
//         }

//         // Detect whether the remote uses us as their main time reference.
//         // if so, we shouldn't sync to them as that would create a loop.
//         // Note, this can only ever be an issue if the source is not using
//         // hardware as its source, so ignore reference_id if stratum is 1.

//         if self.stratum != 1
//             && local_ips
//                 .iter()
//                 .any(|ip| ReferenceId::from_ip(*ip) == self.source_id)
//         {
//             info!("Source rejected because of detected synchronization loop (ref id)");
//             return Err(Loop);
//         }

//         #[cfg(feature = "ntpv5")]
//         match self.bloom_filter {
//             Some(filter) if filter.contains_id(&system.server_id) => {
//                 info!("Source rejected because of detected synchronization loop (bloom filter)");
//                 return Err(Loop);
//             }
//             _ => {}
//         }

       

//         Ok(())
//     }

//     pub fn from_source(source: &GpsSource) -> Self {
//         Self {
           
//         }
//     }

// }

// #[cfg(feature = "__internal-test")]
// pub fn source_snapshot() -> GpsSourceSnapshot {
//     use std::net::Ipv4Addr;

//     let mut reach = crate::source::Reach::default();
//     reach.received_packet();

//     GpsSourceSnapshot {
//         source_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
//         source_id: ReferenceId::from_int(0),
//         stratum: 0,
//         reference_id: ReferenceId::from_int(0),

//         poll_interval: crate::time_types::PollIntervalLimits::default().min,
//         protocol_version: Default::default(),
//         #[cfg(feature = "ntpv5")]
//         bloom_filter: None,
//     }
// }

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AcceptSynchronizationError {
    ServerUnreachable,
    Loop,
    Distance,
    Stratum,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProtocolVersion {
    V4,
    #[cfg(feature = "ntpv5")]
    V4UpgradingToV5 {
        tries_left: u8,
    },
    #[cfg(feature = "ntpv5")]
    V5,
}

impl ProtocolVersion {
    pub fn expected_incoming_version(&self) -> u8 {
        match self {
            ProtocolVersion::V4 => 4,
            #[cfg(feature = "ntpv5")]
            ProtocolVersion::V4UpgradingToV5 { .. } => 4,
            #[cfg(feature = "ntpv5")]
            ProtocolVersion::V5 => 5,
        }
    }
}

impl Default for ProtocolVersion {
    #[cfg(feature = "ntpv5")]
    fn default() -> Self {
        Self::V4UpgradingToV5 { tries_left: 8 }
    }

    #[cfg(not(feature = "ntpv5"))]
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, Copy, Clone)]
pub struct GpsSourceUpdate {
    pub(crate) measurement: Option<Measurement>,
}

#[cfg(feature = "__internal-test")]
impl GpsSourceUpdate {
    pub fn measurement(measurement: Measurement) -> Self {
        GpsSourceUpdate {
            measurement: Some(measurement),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GpsSourceAction {
    /// Send a message over the network. When this is issued, the network port maybe changed.
    Send(Vec<u8>),
    /// Send an update to [`System`](crate::system::System)
    UpdateSystem(GpsSourceUpdate),
    /// Call [`NtpSource::handle_timer`] after given duration
    SetTimer(Duration),
    /// A complete reset of the connection is necessary, including a potential new NTSKE client session and/or DNS lookup.
    Reset,
    /// We must stop talking to this particular server.
    Demobilize,
}

#[derive(Debug)]
pub struct GpsSourceActionIterator {
    iter: <Vec<GpsSourceAction> as IntoIterator>::IntoIter,
}

impl Default for GpsSourceActionIterator {
    fn default() -> Self {
        Self {
            iter: vec![].into_iter(),
        }
    }
}

impl Iterator for GpsSourceActionIterator {
    type Item = GpsSourceAction;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl GpsSourceActionIterator {
    fn from(data: Vec<GpsSourceAction>) -> Self {
        Self {
            iter: data.into_iter(),
        }
    }
}

macro_rules! actions {
    [$($action:expr),*] => {
        {
            GpsSourceActionIterator::from(vec![$($action),*])
        }
    }
}

impl GpsSource {
    #[instrument]
    pub fn new(
    ) -> (Self, GpsSourceActionIterator) {
        (
            Self {
                current_request_identifier: None,
            },
            actions!(GpsSourceAction::SetTimer(Duration::from_secs(0))),
        )
    }
   

   

    // #[cfg_attr(not(feature = "ntpv5"), allow(unused_mut))]
    // pub fn handle_timer(&mut self, system: SystemSnapshot) -> GpsSourceActionIterator {

       
     


       

    //     let poll_interval = self.current_poll_interval(system);
    //     actions!(
    //         // randomize the poll interval a little to make it harder to predict poll requests
    //         GpsSourceAction::SetTimer(
    //             poll_interval
    //                 .as_system_duration()
    //                 .mul_f64(thread_rng().gen_range(1.01..=1.05))
    //         )
    //     )
    // }

    #[instrument(skip(self))]
    pub fn handle_incoming(
        &mut self,
        local_clock_time: NtpInstant,
        send_time: NtpTimestamp,
        recv_time: NtpTimestamp,
    ) -> GpsSourceActionIterator {
        
        // generate a measurement
        let measurement = Measurement::from_gps(
            send_time,
            recv_time,
            local_clock_time,
        );
       
        // info!("set actionupdate");
        actions!(GpsSourceAction::UpdateSystem(GpsSourceUpdate {
            measurement: Some(measurement),
        }))
       
    }
}