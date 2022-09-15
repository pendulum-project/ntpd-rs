use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::subnet::IpSubnet;

pub trait IpAddrContains: Ord + Copy + std::fmt::Debug {
    fn contains(haystack_ip: Self, haystack_mask: u8, needle_ip: Self) -> bool;
}

impl IpAddrContains for Ipv4Addr {
    fn contains(haystack_ip: Self, haystack_mask: u8, needle_ip: Self) -> bool {
        let shifted = |ip: Self| {
            u32::from_be_bytes(ip.octets())
                .checked_shr(32 - haystack_mask as u32)
                .unwrap_or(0)
        };

        shifted(haystack_ip) == shifted(needle_ip)
    }
}

impl IpAddrContains for Ipv6Addr {
    fn contains(haystack_ip: Self, haystack_mask: u8, needle_ip: Self) -> bool {
        let shifted = |ip: Self| {
            u128::from_be_bytes(ip.octets())
                .checked_shr(128 - haystack_mask as u32)
                .unwrap_or(0)
        };

        shifted(haystack_ip) == shifted(needle_ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecIpFilter<T>(Vec<(T, u8)>);

impl<T> Default for VecIpFilter<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<IP: IpAddrContains> VecIpFilter<IP> {
    fn insert(&mut self, new_ip: IP, new_mask: u8) {
        let mut already_covered = false;
        self.0.retain(|(old_ip, old_mask)| {
            // don't add new if already covered by old
            if IP::contains(*old_ip, *old_mask, new_ip) {
                already_covered = true;
            }

            // retain old if not covered by the new mask
            !IP::contains(new_ip, new_mask, *old_ip)
        });

        if !already_covered {
            self.0.push((new_ip, new_mask));
        }

        // sort from biggest to smallest
        self.0.sort_by(|a, b| b.cmp(a))
    }

    fn lookup(&self, needle_ip: &IP) -> bool {
        // exploit that we've sorted from biggest to smallest;
        match self.0.iter().find(|(k, _)| k <= needle_ip) {
            None => false,
            Some((haystack_ip, haystack_mask)) => {
                IP::contains(*haystack_ip, *haystack_mask, *needle_ip)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilter {
    ipv4_filter: VecIpFilter<Ipv4Addr>,
    ipv6_filter: VecIpFilter<Ipv6Addr>,
}

impl IpFilter {
    /// Create a filter from a list of subnets
    /// Complexity: O(n) with n length of list
    pub fn new(subnets: &[IpSubnet]) -> Self {
        let mut ipv4_filter = VecIpFilter::default();
        let mut ipv6_filter = VecIpFilter::default();

        for subnet in subnets {
            match subnet.addr {
                IpAddr::V4(addr) => ipv4_filter.insert(addr, subnet.mask),
                IpAddr::V6(addr) => ipv6_filter.insert(addr, subnet.mask),
            }
        }

        IpFilter {
            ipv4_filter,
            ipv6_filter,
        }
    }

    pub fn all() -> Self {
        Self::new(&[
            IpSubnet {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                mask: 32,
            },
            IpSubnet {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                mask: 128,
            },
        ])
    }

    pub fn none() -> Self {
        IpFilter {
            ipv4_filter: Default::default(),
            ipv6_filter: Default::default(),
        }
    }

    /// Check whether a given ip address is contained in the filter.
    /// Complexity: O(n), but easy to vectorize
    pub fn is_in(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => self.ipv4_filter.lookup(addr),
            IpAddr::V6(addr) => self.ipv6_filter.lookup(addr),
        }
    }
}

//#[cfg(fuzz)]
pub mod fuzz {
    use super::*;

    fn contains(subnet: &IpSubnet, addr: &IpAddr) -> bool {
        match (subnet.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net = u32::from_be_bytes(net.octets());
                let addr = u32::from_be_bytes(addr.octets());
                let mask = 0xFFFFFFFF_u32
                    .checked_shl((32 - subnet.mask) as u32)
                    .unwrap_or(0);
                (net & mask) == (addr & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net = u128::from_be_bytes(net.octets());
                let addr = u128::from_be_bytes(addr.octets());
                let mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u128
                    .checked_shl((128 - subnet.mask) as u32)
                    .unwrap_or(0);
                (net & mask) == (addr & mask)
            }
            _ => false,
        }
    }

    fn any_contains(subnets: &[IpSubnet], addr: &IpAddr) -> bool {
        for net in subnets {
            if contains(net, addr) {
                return true;
            }
        }
        false
    }

    pub fn fuzz_ipfilter(nets: &[IpSubnet], addr: &[IpAddr]) {
        let filter = IpFilter::new(nets);

        for addr in addr {
            assert_eq!(filter.is_in(addr), any_contains(nets, addr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter() {
        let filter = IpFilter::new(&[
            "127.0.0.0/24".parse().unwrap(),
            "::FFFF:0000:0000/96".parse().unwrap(),
        ]);
        assert!(filter.is_in(&"127.0.0.1".parse().unwrap()));
        assert!(!filter.is_in(&"192.168.1.1".parse().unwrap()));
        assert!(filter.is_in(&"::FFFF:ABCD:0123".parse().unwrap()));
        assert!(!filter.is_in(&"::FEEF:ABCD:0123".parse().unwrap()));
    }

    #[test]
    fn test_subnet_edgecases() {
        let filter = IpFilter::new(&["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);

        assert!(filter.is_in(&"0.0.0.0".parse().unwrap()));
        assert!(filter.is_in(&"255.255.255.255".parse().unwrap()));
        assert!(filter.is_in(&"::".parse().unwrap()));
        assert!(filter.is_in(&"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF".parse().unwrap()));

        let filter = IpFilter::new(&[
            "1.2.3.4/32".parse().unwrap(),
            "10:32:54:76:98:BA:DC:FE/128".parse().unwrap(),
        ]);

        assert!(filter.is_in(&"1.2.3.4".parse().unwrap()));
        assert!(!filter.is_in(&"1.2.3.5".parse().unwrap()));
        assert!(filter.is_in(&"10:32:54:76:98:BA:DC:FE".parse().unwrap()));
        assert!(!filter.is_in(&"10:32:54:76:98:BA:DC:FF".parse().unwrap()));
    }
}
