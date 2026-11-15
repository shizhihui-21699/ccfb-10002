//! Shared low-level parsing helpers: IPs, CIDRs, ports, protocols.

use crate::rect::{Family, IntervalSet, Rect, DIM_DPORT, DIM_DST, DIM_PROTO, DIM_SPORT, DIM_SRC};

/// Parse "addr[/prefix]" or "addr/netmask" into (family, lo, hi).
/// Also accepts a bare range "addr-addr".
pub fn parse_addr_spec(s: &str) -> Option<(Family, u128, u128)> {
    if let Some((a, b)) = s.split_once('-') {
        let (fa, la) = parse_ip(a)?;
        let (fb, lb) = parse_ip(b)?;
        if fa != fb {
            return None;
        }
        return Some((fa, la, lb));
    }
    let (addr_part, prefix_part) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let (fam, addr) = parse_ip(addr_part)?;
    let bits = match fam {
        Family::V4 => 32u32,
        Family::V6 => 128u32,
    };
    let prefix: u32 = match prefix_part {
        None => bits,
        Some(p) => {
            if let Ok(n) = p.parse::<u32>() {
                if n > bits {
                    return None;
                }
                n
            } else if fam == Family::V4 {
                // dotted netmask, e.g. 255.255.240.0
                let (_, mask) = parse_ip(p)?;
                let m = mask as u32;
                let prefix = m.leading_ones();
                let contiguous = if prefix == 0 {
                    m == 0
                } else {
                    m == u32::MAX << (32 - prefix)
                };
                if !contiguous {
                    return None;
                }
                prefix
            } else {
                return None;
            }
        }
    };
    let host_bits = bits - prefix;
    let (lo, hi) = if host_bits == 0 {
        (addr, addr)
    } else {
        let mask = if host_bits >= 128 {
            0u128
        } else {
            u128::MAX.checked_shr(host_bits).unwrap_or(0).checked_shl(host_bits).unwrap_or(0)
        };
        let lo = addr & mask;
        let hi = lo | (!mask & family_max(fam));
        (lo, hi)
    };
    Some((fam, lo, hi))
}

fn family_max(f: Family) -> u128 {
    match f {
        Family::V4 => u32::MAX as u128,
        Family::V6 => u128::MAX,
    }
}

/// Parse a single IPv4 or IPv6 address.
pub fn parse_ip(s: &str) -> Option<(Family, u128)> {
    if s.contains(':') {
        parse_ipv6(s).map(|v| (Family::V6, v))
    } else {
        parse_ipv4(s).map(|v| (Family::V4, v))
    }
}

pub fn parse_ipv4(s: &str) -> Option<u128> {
    let mut parts = [0u8; 4];
    let mut n = 0;
    for p in s.split('.') {
        if n >= 4 || p.is_empty() || p.len() > 3 {
            return None;
        }
        parts[n] = p.parse().ok()?;
        n += 1;
    }
    if n != 4 {
        return None;
    }
    Some(u32::from_be_bytes(parts) as u128)
}

pub fn parse_ipv6(s: &str) -> Option<u128> {
    // handle "::" compression
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let mut groups: Vec<u16> = Vec::new();
    let parse_groups = |part: &str, out: &mut Vec<u16>| -> Option<()> {
        if part.is_empty() {
            return Some(());
        }
        for g in part.split(':') {
            // embedded IPv4, e.g. ::ffff:1.2.3.4
            if g.contains('.') {
                let v4 = parse_ipv4(g)? as u32;
                out.push((v4 >> 16) as u16);
                out.push((v4 & 0xffff) as u16);
            } else {
                if g.len() > 4 {
                    return None;
                }
                out.push(u16::from_str_radix(g, 16).ok()?);
            }
        }
        Some(())
    };
    parse_groups(head, &mut groups)?;
    let mut tail_groups: Vec<u16> = Vec::new();
    if let Some(t) = tail {
        parse_groups(t, &mut tail_groups)?;
    }
    let total = groups.len() + tail_groups.len();
    if total > 8 || (tail.is_none() && total != 8) {
        return None;
    }
    let zeros = 8 - total;
    let mut all = Vec::with_capacity(8);
    all.extend_from_slice(&groups);
    all.extend(std::iter::repeat(0u16).take(zeros));
    all.extend_from_slice(&tail_groups);
    let mut v = 0u128;
    for g in all {
        v = (v << 16) | g as u128;
    }
    Some(v)
}

/// CIDR complement within the family address space.
pub fn complement(fam: Family, lo: u128, hi: u128) -> IntervalSet {
    let max = family_max(fam);
    let full = IntervalSet::full(max);
    full.subtract(&IntervalSet::single(lo, hi))
}

pub fn proto_number(s: &str) -> Option<u8> {
    if let Ok(n) = s.parse::<u8>() {
        return Some(n);
    }
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" | "ipv6-icmp" => Some(58),
        "igmp" => Some(2),
        "gre" => Some(47),
        "esp" => Some(50),
        "ah" => Some(51),
        "sctp" => Some(132),
        "udplite" => Some(136),
        "ospf" => Some(89),
        "all" => Some(0), // caller treats 0 specially for iptables "-p all"
        _ => None,
    }
}

pub fn service_port(s: &str) -> Option<u16> {
    if let Ok(n) = s.parse::<u16>() {
        return Some(n);
    }
    match s.to_ascii_lowercase().as_str() {
        "ftp-data" => Some(20),
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "domain" | "dns" => Some(53),
        "http" => Some(80),
        "pop3" => Some(110),
        "ntp" => Some(123),
        "imap" => Some(143),
        "snmp" => Some(161),
        "ldap" => Some(389),
        "https" => Some(443),
        "smtps" => Some(465),
        "submission" => Some(587),
        "imaps" => Some(993),
        "pop3s" => Some(995),
        "mysql" => Some(3306),
        "rdp" => Some(3389),
        "postgresql" | "postgres" => Some(5432),
        "redis" => Some(6379),
        "vnc" => Some(5900),
        _ => None,
    }
}

/// "80", "1000:2000" (iptables), "1000-2000" (nft) -> (lo, hi)
pub fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once(':').or_else(|| s.split_once('-')) {
        let lo = service_port(a)?;
        let hi = service_port(b)?;
        Some((lo.min(hi), lo.max(hi)))
    } else {
        let p = service_port(s)?;
        Some((p, p))
    }
}

/// Accumulates match constraints for one rule, then expands to rects
/// (one per address family).
pub struct RuleBuilder {
    pub fam: Option<Family>,
    pub src: Option<(Family, IntervalSet)>,
    pub dst: Option<(Family, IntervalSet)>,
    pub proto: Option<IntervalSet>,
    pub sport: Option<IntervalSet>,
    pub dport: Option<IntervalSet>,
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub atoms: Vec<String>,
    pub target: Option<(String, bool)>, // (raw target, is_goto)
}

impl RuleBuilder {
    pub fn new() -> Self {
        RuleBuilder {
            fam: None,
            src: None,
            dst: None,
            proto: None,
            sport: None,
            dport: None,
            iif: None,
            oif: None,
            atoms: Vec::new(),
            target: None,
        }
    }

    pub fn set_family(&mut self, f: Family) {
        self.fam = Some(f);
    }

    pub fn build(self) -> Vec<Rect> {
        let fams: Vec<Family> = match self.fam {
            Some(f) => vec![f],
            None => vec![Family::V4, Family::V6],
        };
        let mut out = Vec::with_capacity(fams.len());
        for f in fams {
            let mut r = Rect::full(f);
            if let Some((sf, ivs)) = &self.src {
                if *sf == f {
                    r.dims[DIM_SRC] = ivs.clone();
                } else {
                    continue; // address of other family: rule can't match this family
                }
            }
            if let Some((df, ivs)) = &self.dst {
                if *df == f {
                    r.dims[DIM_DST] = ivs.clone();
                } else {
                    continue;
                }
            }
            if let Some(p) = &self.proto {
                r.dims[DIM_PROTO] = p.clone();
            }
            if let Some(s) = &self.sport {
                r.dims[DIM_SPORT] = s.clone();
            }
            if let Some(d) = &self.dport {
                r.dims[DIM_DPORT] = d.clone();
            }
            r.iif = self.iif.clone();
            r.oif = self.oif.clone();
            r.atoms = self.atoms.iter().cloned().collect();
            out.push(r);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4() {
        assert_eq!(parse_ipv4("10.0.0.1"), Some(0x0A000001));
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
    }

    #[test]
    fn test_cidr() {
        let (f, lo, hi) = parse_addr_spec("10.0.0.0/8").unwrap();
        assert_eq!(f, Family::V4);
        assert_eq!(lo, 0x0A000000);
        assert_eq!(hi, 0x0AFFFFFF);
        let (_, lo, hi) = parse_addr_spec("192.168.1.7").unwrap();
        assert_eq!(lo, hi);
        let (_, lo, hi) = parse_addr_spec("10.0.0.0/255.255.0.0").unwrap();
        assert_eq!((lo, hi), (0x0A000000, 0x0A00FFFF));
        let (_, lo, hi) = parse_addr_spec("0.0.0.0/0").unwrap();
        assert_eq!((lo, hi), (0, u32::MAX as u128));
    }

    #[test]
    fn test_v6() {
        assert_eq!(parse_ipv6("::1"), Some(1));
        assert_eq!(parse_ipv6("::"), Some(0));
        assert_eq!(
            parse_ipv6("2001:db8::1"),
            Some(0x20010db8000000000000000000000001u128)
        );
        assert_eq!(parse_ipv6("fe80::ffff:1.2.3.4").is_some(), true);
        let (f, lo, hi) = parse_addr_spec("fd00::/8").unwrap();
        assert_eq!(f, Family::V6);
        assert_eq!(lo, 0xfd000000000000000000000000000000u128);
        assert_eq!(hi, 0xfdffffffffffffffffffffffffffffffu128);
    }

    #[test]
    fn test_complement() {
        let c = complement(Family::V4, 0x0A000000, 0x0AFFFFFF);
        assert_eq!(
            c.ivs,
            vec![(0, 0x09FFFFFF), (0x0B000000, u32::MAX as u128)]
        );
    }

    #[test]
    fn test_ports() {
        assert_eq!(parse_port_range("80"), Some((80, 80)));
        assert_eq!(parse_port_range("1000:2000"), Some((1000, 2000)));
        assert_eq!(parse_port_range("1000-2000"), Some((1000, 2000)));
        assert_eq!(parse_port_range("ssh"), Some((22, 22)));
    }
}
