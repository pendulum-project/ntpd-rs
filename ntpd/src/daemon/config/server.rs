use std::net::SocketAddr;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use statime_config::{Configurable, ConfigurableAtomic, Positive, serde_util::Content};

use crate::daemon::{
    config::{ConfigurableDuration, IpSubnet, Unit, primitives::NtpVersion},
    server,
};

#[derive(Debug, Clone, PartialEq, Configurable)]
#[config(tag = "type")]
pub(crate) enum ServerConfig {
    Ntp(NtpServerConfig),
}

#[derive(Debug, Clone, PartialEq, Configurable)]
pub(crate) struct NtpServerConfig {
    pub(crate) listen: SocketAddr,
    #[config(default = FilterList { ranges: vec![], action: FilterAction::Deny })]
    pub(crate) denylist: FilterList,
    #[config(default = FilterList { ranges: vec!["::0/0".parse().unwrap(), "0.0.0.0/0".parse().unwrap()], action: FilterAction::Ignore })]
    pub(crate) allowlist: FilterList,
    #[config(rename = "rate-limiting-cache-size", default = 0)]
    pub(crate) rate_limiting_cache_size: usize,
    #[config(rename = "rate-limiting-cutoff", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1.0 }))]
    pub(crate) rate_limiting_cutoff: Positive<ConfigurableDuration>,
    #[config(rename = "require-nts", default = RequireNts::Implicit(false))]
    pub(crate) require_nts: RequireNts,
    #[config(rename = "accept-ntp-versions", default = vec![NtpVersion::V3, NtpVersion::V4])]
    pub(crate) accept_ntp_versions: Vec<NtpVersion>,
    // Experimental
    #[config(rename = "network-wait-period", default = Positive::unchecked_new(ConfigurableDuration { unit: Unit::Second, duration: 1.0 }))]
    pub(crate) network_wait_period: Positive<ConfigurableDuration>,
}

impl NtpServerConfig {
    pub(crate) fn generate_server_config(&self) -> server::ServerConfig {
        server::ServerConfig {
            listen: self.listen,
            denylist: self.denylist.clone().into(),
            allowlist: self.allowlist.clone().into(),
            rate_limiting_cache_size: self.rate_limiting_cache_size,
            rate_limiting_cutoff: ConfigurableDuration::into_std_duration(
                self.rate_limiting_cutoff,
            ),
            require_nts: self.require_nts.into(),
            accept_ntp_versions: self
                .accept_ntp_versions
                .clone()
                .into_iter()
                .map(ntp_proto::NtpVersion::from)
                .collect(),
            network_wait_period: ConfigurableDuration::into_std_duration(self.network_wait_period),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ConfigurableAtomic, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FilterAction {
    Deny,
    Ignore,
}

impl From<FilterAction> for ntp_proto::FilterAction {
    fn from(value: FilterAction) -> Self {
        match value {
            FilterAction::Deny => ntp_proto::FilterAction::Deny,
            FilterAction::Ignore => ntp_proto::FilterAction::Ignore,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ConfigurableAtomic, Serialize, Deserialize)]
pub(crate) struct FilterList {
    ranges: Vec<IpSubnet>,
    action: FilterAction,
}

impl From<FilterList> for ntp_proto::FilterList {
    fn from(value: FilterList) -> Self {
        Self {
            filter: value
                .ranges
                .into_iter()
                .map(ntp_proto::IpSubnet::from)
                .collect(),
            action: value.action.into(),
        }
    }
}

/// Requiring nts can be specified as either a boolean or an explicit filtering action.
/// This struct handles the (de)serialization of this setting, keeping the representation
/// explicit in the config parsing process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ConfigurableAtomic, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum RequireNts {
    Implicit(bool),
    Explicit(FilterAction),
}

impl From<RequireNts> for Option<ntp_proto::FilterAction> {
    fn from(value: RequireNts) -> Self {
        match value {
            RequireNts::Implicit(false) => None,
            RequireNts::Implicit(true) => Some(ntp_proto::FilterAction::Ignore),
            RequireNts::Explicit(filter_action) => Some(filter_action.into()),
        }
    }
}
