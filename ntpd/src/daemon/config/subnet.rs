use serde::{de, Deserialize, Deserializer};
use std::{
    fmt::Display,
    net::{AddrParseError, IpAddr},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSubnet {
    pub addr: IpAddr,
    pub mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetParseError {
    Subnet,
    Ip(AddrParseError),
    Mask,
}

impl std::error::Error for SubnetParseError {}

impl Display for SubnetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subnet => write!(f, "Invalid subnet syntax"),
            Self::Ip(e) => write!(f, "{e} in subnet"),
            Self::Mask => write!(f, "Invalid subnet mask"),
        }
    }
}

impl From<AddrParseError> for SubnetParseError {
    fn from(value: AddrParseError) -> Self {
        Self::Ip(value)
    }
}

impl std::str::FromStr for IpSubnet {
    type Err = SubnetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = s.split_once('/').ok_or(SubnetParseError::Subnet)?;
        let addr: IpAddr = addr.parse()?;
        let mask: u8 = mask.parse().map_err(|_| SubnetParseError::Mask)?;
        let max_mask = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if mask > max_mask {
            return Err(SubnetParseError::Mask);
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
