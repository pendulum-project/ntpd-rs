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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NtsKeConfig {
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub accepted_pool_authentication_tokens: Vec<String>,
    pub key_exchange_timeout_ms: u64,
    pub concurrent_connections: usize,
    pub longlived_connections: usize,
    pub listen: SocketAddr,
    pub ntp_port: Option<u16>,
    pub ntp_server: Option<String>,
    pub accept_ntp_versions: Vec<NtpVersion>,
}
