//! Which peers the relay may talk to. A TURN server sends UDP wherever an authenticated client
//! asks, so without this it would be a way into the server's own network (SSRF): loopback
//! services, cloud metadata endpoints, the LAN.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::TurnPeers;

/// An IP network such as `192.168.1.0/24` or `fd00::/8` (a bare address is a /32 or /128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub const fn v4(a: [u8; 4], prefix: u8) -> Cidr {
        Cidr { addr: IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])), prefix }
    }

    pub const fn v6(segments: [u16; 8], prefix: u8) -> Cidr {
        let s = segments;
        Cidr { addr: IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])), prefix }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Cidr, String> {
        let bad = || format!("\"{s}\" isn't a network like 192.168.1.0/24.");
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(bad)?,
            None => max,
        };
        Ok(Cidr { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Cidr, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Cloud metadata and host-agent endpoints. Never relayed to, whatever the config says about
/// private networks: they hand out credentials to anyone who can reach them.
const METADATA: &[Cidr] = &[
    Cidr::v4([169, 254, 0, 0], 16),                         // link-local, incl. 169.254.169.254 (AWS, GCP, Azure…)
    Cidr::v4([100, 100, 100, 200], 32),                     // Alibaba Cloud
    Cidr::v4([168, 63, 129, 16], 32),                       // Azure WireServer
    Cidr::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128), // AWS over IPv6
];

/// Addresses that are never real peers: unspecified, "this network", multicast, broadcast,
/// reserved and documentation ranges.
const BOGONS: &[Cidr] = &[
    Cidr::v4([0, 0, 0, 0], 8),
    Cidr::v4([192, 0, 0, 0], 24),
    Cidr::v4([192, 0, 2, 0], 24),
    Cidr::v4([198, 18, 0, 0], 15),
    Cidr::v4([198, 51, 100, 0], 24),
    Cidr::v4([203, 0, 113, 0], 24),
    Cidr::v4([224, 0, 0, 0], 4),
    Cidr::v4([240, 0, 0, 0], 4),
    Cidr::v6([0, 0, 0, 0, 0, 0, 0, 0], 128),
    Cidr::v6([0x0100, 0, 0, 0, 0, 0, 0, 0], 64),
    Cidr::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
    Cidr::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    Cidr::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// Private networks: refused unless `turn.peers.allow_private` is on, since they're the server's
/// own LAN. Two phones on one home network don't need them: when their direct path fails they
/// meet through their relayed addresses, which the relay connects without sending anywhere.
const PRIVATE: &[Cidr] = &[
    Cidr::v4([10, 0, 0, 0], 8),
    Cidr::v4([172, 16, 0, 0], 12),
    Cidr::v4([192, 168, 0, 0], 16),
    Cidr::v4([100, 64, 0, 0], 10),
    Cidr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];

/// The peer rules from the config, ready for per-request checks.
#[derive(Debug, Clone)]
pub struct PeerPolicy {
    allow_private: bool,
    allow_loopback: bool,
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
}

impl PeerPolicy {
    pub fn new(c: &TurnPeers) -> PeerPolicy {
        PeerPolicy { allow_private: c.allow_private, allow_loopback: c.allow_loopback, allow: c.allow.clone(), deny: c.deny.clone() }
    }

    /// Whether `ip` is allowed by an explicit choice (the allow list, or loopback when that's
    /// turned on) rather than by default, so even the server's own addresses may be reached.
    pub fn explicitly_allows(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.allow.iter().any(|c| c.contains(ip)) || (self.allow_loopback && ip.is_loopback())
    }

    /// Whether a client may relay to `ip`.
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if self.allow.iter().any(|c| c.contains(ip)) {
            return true;
        }
        if self.deny.iter().any(|c| c.contains(ip)) || METADATA.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        if BOGONS.iter().any(|c| c.contains(ip)) || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return false;
        }
        if PRIVATE.iter().any(|c| c.contains(ip)) {
            return self.allow_private;
        }
        true
    }
}

/// IPv4 written as IPv6 (`::ffff:127.0.0.1`, NAT64 `64:ff9b::7f00:1`) is checked as the IPv4
/// address it reaches, so the rules can't be dodged by spelling.
pub(super) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let o = v6.octets();
                return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
            }
            IpAddr::V6(v6)
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(f: impl FnOnce(&mut TurnPeers)) -> PeerPolicy {
        let mut c = TurnPeers::default();
        f(&mut c);
        PeerPolicy::new(&c)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_allowed() {
        let p = policy(|_| {});
        assert!(p.allows(ip("8.8.8.8")));
        assert!(p.allows(ip("2a00:1450::1")));
    }

    #[test]
    fn loopback_is_refused_by_default_in_every_spelling() {
        let p = policy(|_| {});
        for a in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"] {
            assert!(!p.allows(ip(a)), "{a}");
        }
        assert!(policy(|c| c.allow_loopback = true).allows(ip("127.0.0.1")));
    }

    #[test]
    fn metadata_endpoints_are_refused_even_with_private_allowed() {
        let p = policy(|c| c.allow_private = true);
        for a in ["169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            assert!(!p.allows(ip(a)), "{a}");
        }
    }

    #[test]
    fn bogons_are_refused() {
        let p = policy(|_| {});
        for a in ["0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "::", "fe80::1", "ff02::1", "240.0.0.1"] {
            assert!(!p.allows(ip(a)), "{a}");
        }
    }

    #[test]
    fn private_networks_follow_the_setting_and_are_off_by_default() {
        let on = policy(|c| c.allow_private = true);
        let off = policy(|_| {});
        for a in ["10.0.0.5", "172.20.1.1", "192.168.1.20", "100.64.0.1", "fd12::1"] {
            assert!(on.allows(ip(a)), "{a}");
            assert!(!off.allows(ip(a)), "{a}");
        }
        assert!(off.allows(ip("172.32.0.1")));
    }

    #[test]
    fn allow_and_deny_lists_win() {
        let p = policy(|c| {
            c.allow_private = false;
            c.allow = vec!["192.168.7.0/24".parse().unwrap()];
            c.deny = vec!["8.8.0.0/16".parse().unwrap()];
        });
        assert!(p.allows(ip("192.168.7.9")));
        assert!(!p.allows(ip("192.168.8.9")));
        assert!(!p.allows(ip("8.8.8.8")));
        assert!(p.allows(ip("8.9.8.8")));
    }

    #[test]
    fn cidrs_parse_and_print() {
        assert_eq!("10.0.0.0/8".parse::<Cidr>().unwrap().to_string(), "10.0.0.0/8");
        assert_eq!("::1".parse::<Cidr>().unwrap().to_string(), "::1/128");
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nope/8".parse::<Cidr>().is_err());
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("1.2.3.4")));
        assert!(!all.contains(ip("::1")));
    }
}
