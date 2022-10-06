use serde::{de, Deserialize, Deserializer};
use std::net::{AddrParseError, IpAddr};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSubnet {
    pub addr: IpAddr,
    pub mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubnetParseError {
    #[error("Invalid subnet syntax")]
    InvalidSubnet,
    #[error("{0} in subnet")]
    InvalidIp(#[from] AddrParseError),
    #[error("Invalid subnet mask")]
    InvalidMask,
}

impl std::str::FromStr for IpSubnet {
    type Err = SubnetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = s.split_once('/').ok_or(SubnetParseError::InvalidSubnet)?;
        let addr: IpAddr = addr.parse()?;
        let mask: u8 = mask.parse().map_err(|_| SubnetParseError::InvalidMask)?;
        let max_mask = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if mask > max_mask {
            return Err(SubnetParseError::InvalidMask);
        }
        Ok(IpSubnet { addr, mask })
    }
}

impl<'de> Deserialize<'de> for IpSubnet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_parsing() {
        let a = "0.0.0.0/0".parse::<IpSubnet>().unwrap();
        assert_eq!(a.mask, 0);
    }
}
