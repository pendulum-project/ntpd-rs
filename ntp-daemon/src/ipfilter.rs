use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::subnet::IpSubnet;

/// One part of a BitTree
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
struct Treenode {
    // Where in the array the child nodes of this
    // node are located. A child node is only
    // generated if the symbol cannot be used to
    // make a final decision at this level
    child_offset: u32,
    inset: u16,
    outset: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// BitTree is a Trie on 128 bit integers encoding
/// which integers are part of the set.
///
/// It matches the integer a 4-bit segment at a time
/// recording at each level whether for a given symbol
/// all integers with the prefix extended with that
/// symbol are either in or outside of the set.
struct BitTree {
    nodes: Vec<Treenode>,
}

fn top_quad(v: u128) -> u8 {
    ((v & (0xF << 124)) >> 124) as u8
}

impl BitTree {
    #[allow(dead_code)]
    /// Lookup whether a given value is in the set encoded in this BitTree
    /// Complexity is O(log(l)), where l is the length of the longest
    /// prefix in the set.
    fn lookup(&self, mut val: u128) -> bool {
        let mut node = &self.nodes[0];
        loop {
            // extract the current symbol as bit and see if we know the answer immediately.
            // (example: symbol 1 maps to 0x2, symbol 5 maps to 0x10)
            let cur = 1 << top_quad(val);
            if node.inset & cur != 0 {
                return true;
            }
            if node.outset & cur != 0 {
                return false;
            }
            // no decision, shift to next symbol
            val <<= 4;
            // To calculate the child index we need to know how many symbols smaller
            // than our symbol are not decided here. We do this by generating the bitmap
            // of symbols neither in in or out, then masking out all symbols >=cur
            // and finaly counting how many are left.
            let next_idx =
                node.child_offset + (!(node.inset | node.outset) & (cur - 1)).count_ones();
            node = &self.nodes[next_idx as usize];
        }
    }

    #[allow(dead_code)]
    /// Create a BitTree from the given prefixes. Complexity is O(n*log(l)),
    /// where n is the number of prefixes, and l the length of the longest
    /// prefix.
    fn create(data: &mut [(u128, u8)]) -> Self {
        // Ensure values only have 1s in significant positions
        for (val, len) in data.iter_mut() {
            *val &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u128
                .checked_shl((128 - *len) as u32)
                .unwrap_or(0);
        }
        // Ensure values are sorted by value and then by length
        data.sort_by(
            |(v1, l1), (v2, l2)| {
                if *v1 != *v2 {
                    v1.cmp(v2)
                } else {
                    l1.cmp(l2)
                }
            },
        );

        let mut result = BitTree {
            nodes: [Treenode::default()].into(),
        };
        result.fill_node(data, 0);
        result
    }

    /// Create the substructure for a node, recursively.
    /// Max recursion depth is maximum value of data[i].1/4
    /// for any i
    fn fill_node(&mut self, mut data: &mut [(u128, u8)], node_idx: usize) {
        // Figure out how the data splits over the 16 segments
        // in this node.
        let mut first_idx = [0; 16];
        let mut last = 0;
        for (idx, (val, _)) in data.iter().enumerate() {
            let cur = top_quad(*val);
            if cur != last {
                for i in last + 1..=cur {
                    first_idx[i as usize] = idx
                }
                last = cur;
            }
        }
        for i in last + 1..16 {
            first_idx[i as usize] = data.len();
        }

        // Actually split into the relevant subsegments
        let mut segs = <[&mut [(u128, u8)]; 16]>::default();
        for i in 0..15 {
            (segs[i], data) = data.split_at_mut(first_idx[i + 1] - first_idx[i]);
        }
        segs[15] = data;

        // Fill in node
        let mut child_offset = self.nodes.len();
        let node = &mut self.nodes[node_idx];
        node.child_offset = child_offset as u32;
        for (i, seg) in segs.iter().enumerate() {
            match seg.first() {
                // Probably empty, unless covered earlier, but we fix that later
                None => node.outset |= 1 << i,
                // Definetly covered, mark all that is needed
                Some((_, len)) if *len <= 4 => {
                    // mark ALL parts of node covered by the segment as in the set.
                    for j in 0..(1 << (4 - *len)) {
                        node.inset |= 1 << (i + j as usize)
                    }
                }
                // Probably not known, we deal with those later.
                _ => {}
            }
        }
        // compensate for incorrectly marked outsets due to overcoverage
        node.outset &= !node.inset;

        let known_bitmap = node.inset | node.outset;
        // allocate nodes
        self.nodes.resize(
            self.nodes.len() + (!known_bitmap).count_ones() as usize,
            Treenode::default(),
        );
        // Create children for segments undecided at this level.
        for (i, seg) in segs.iter_mut().enumerate() {
            if known_bitmap & (1 << i) != 0 {
                continue; // no child needed
            }
            for (val, len) in seg.iter_mut() {
                *val <<= 4;
                *len -= 4;
            }
            self.fill_node(seg, child_offset);
            child_offset += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilter {
    ipv4filter: BitTree,
    ipv6filter: BitTree,
}

impl IpFilter {
    /// Create a filter from a list of subnets
    /// Complexity: O(n) with n length of list
    pub fn new(subnets: &[IpSubnet]) -> Self {
        let mut ipv4list = Vec::new();
        let mut ipv6list = Vec::new();

        for subnet in subnets {
            match subnet.addr {
                IpAddr::V4(addr) => ipv4list.push((
                    (u32::from_be_bytes(addr.octets()) as u128) << 96,
                    subnet.mask,
                )),
                IpAddr::V6(addr) => {
                    ipv6list.push((u128::from_be_bytes(addr.octets()), subnet.mask))
                }
            }
        }

        IpFilter {
            ipv4filter: BitTree::create(ipv4list.as_mut_slice()),
            ipv6filter: BitTree::create(ipv6list.as_mut_slice()),
        }
    }

    pub fn all() -> Self {
        let mut temp_v4 = [(0, 0)];
        let mut temp_v6 = [(0, 0)];
        IpFilter {
            ipv4filter: BitTree::create(&mut temp_v4),
            ipv6filter: BitTree::create(&mut temp_v6),
        }
    }

    pub fn none() -> Self {
        let mut temp_v4 = [];
        let mut temp_v6 = [];
        IpFilter {
            ipv4filter: BitTree::create(&mut temp_v4),
            ipv6filter: BitTree::create(&mut temp_v6),
        }
    }

    /// Check whether a given ip address is contained in the filter.
    /// Complexity: O(1)
    pub fn is_in(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => self.is_in4(addr),
            IpAddr::V6(addr) => self.is_in6(addr),
        }
    }

    fn is_in4(&self, addr: &Ipv4Addr) -> bool {
        self.ipv4filter
            .lookup((u32::from_be_bytes(addr.octets()) as u128) << 96)
    }

    fn is_in6(&self, addr: &Ipv6Addr) -> bool {
        self.ipv6filter.lookup(u128::from_be_bytes(addr.octets()))
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
    fn test_bittree() {
        let mut data = [
            (0x10 << 120, 4),
            (0x20 << 120, 3),
            (0x43 << 120, 8),
            (0x82 << 120, 7),
        ];
        let tree = BitTree::create(&mut data);
        assert!(tree.lookup(0x11 << 120));
        assert!(!tree.lookup(0x40 << 120));
        assert!(tree.lookup(0x30 << 120));
        assert!(tree.lookup(0x43 << 120));
        assert!(!tree.lookup(0xC4 << 120));
        assert!(tree.lookup(0x82 << 120));
        assert!(tree.lookup(0x83 << 120));
        assert!(!tree.lookup(0x81 << 120));
    }

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
