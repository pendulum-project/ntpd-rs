use std::{
    net::{AddrParseError, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use ntp_proto::{FilterAction, FilterList, NtpVersion};
use serde::{Deserialize, Deserializer};
use statime_config::Configurable;

#[derive(Debug, Clone, PartialEq, Eq, Configurable)]
pub struct NtpServerConfig {}
