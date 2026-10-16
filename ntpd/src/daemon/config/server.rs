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
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub denylist: FilterList,
    pub allowlist: FilterList,
    pub rate_limiting_cache_size: usize,
    pub rate_limiting_cutoff: Duration,
    pub require_nts: Option<FilterAction>,
    pub accept_ntp_versions: Vec<NtpVersion>,
}

#[cfg(test)]
impl From<SocketAddr> for ServerConfig {
    fn from(listen: SocketAddr) -> Self {
        ServerConfig {
            listen,
            denylist: FilterList {
                filter: vec![],
                action: ntp_proto::FilterAction::Deny,
            },
            allowlist: FilterList {
                filter: vec!["::/0".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
                action: ntp_proto::FilterAction::Ignore,
            },
            rate_limiting_cache_size: 0,
            rate_limiting_cutoff: Duration::default(),
            require_nts: None,
            accept_ntp_versions: vec![NtpVersion::V3, NtpVersion::V4],
        }
    }
}

impl From<ServerConfig> for ntp_proto::ServerConfig {
    fn from(value: ServerConfig) -> Self {
        ntp_proto::ServerConfig {
            denylist: value.denylist,
            allowlist: value.allowlist,
            rate_limiting_cache_size: value.rate_limiting_cache_size,
            rate_limiting_cutoff: value.rate_limiting_cutoff,
            require_nts: value.require_nts,
            accepted_versions: value.accept_ntp_versions,
        }
    }
}

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
