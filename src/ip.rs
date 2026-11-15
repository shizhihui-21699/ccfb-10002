//! IP 地址与 CIDR：全部转成整数区间做精确集合运算。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Family {
    #[default]
    V4,
    V6,
}

impl Family {
    pub fn bits(self) -> u32 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    pub fn max_value(self) -> u128 {
        match self {
            Family::V4 => u32::MAX as u128,
            Family::V6 => u128::MAX,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::V4 => "ip",
            Family::V6 => "ip6",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddr {
    pub family: Family,
    pub value: u128,
}

impl IpAddr {
    pub fn v4(octets: [u8; 4]) -> Self {
        IpAddr {
            family: Family::V4,
            value: u32::from_be_bytes(octets) as u128,
        }
    }

    pub fn parse(s: &str) -> Result<IpAddr, String> {
        if s.contains(':') {
            parse_v6(s)
        } else {
            parse_v4(s).map(|v| IpAddr {
                family: Family::V4,
                value: v as u128,
            })
        }
    }

    pub fn format(self) -> String {
        match self.family {
            Family::V4 => format_v4(self.value as u32),
            Family::V6 => format_v6(self.value),
        }
    }
}

fn parse_v4(s: &str) -> Result<u32, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("非法 IPv4 地址: {s}"));
    }
    let mut v: u32 = 0;
    for p in parts {
        let o: u32 = p
            .parse()
            .map_err(|_| format!("IPv4 段不是数字: {p} (在 {s} 中)"))?;
        if o > 255 {
            return Err(format!("IPv4 段超出范围: {p} (在 {s} 中)"));
        }
        v = (v << 8) | o;
    }
    Ok(v)
}

fn format_v4(v: u32) -> String {
    let o = v.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn parse_v6(s: &str) -> Result<IpAddr, String> {
    // 先剥离可能内嵌的 IPv4 尾段（::ffff:192.0.2.1），转成两个 16 位组。
    let (main, v4_groups): (&str, Vec<u16>) = if let Some(dot) = s.rfind('.') {
        let colon = s[..dot]
            .rfind(':')
            .ok_or_else(|| format!("非法 IPv6: {s}"))?;
        let v4 = parse_v4(&s[colon + 1..])?;
        (&s[..colon], vec![(v4 >> 16) as u16, (v4 & 0xffff) as u16])
    } else {
        (s, Vec::new())
    };

    // 至多一个 ::
    let double_colon = main.find("::");
    if let Some(pos) = double_colon {
        if main[pos + 2..].contains("::") {
            return Err(format!("非法 IPv6（多个 ::）: {s}"));
        }
    }

    // 把冒号分隔的一段解析成 16 位组（空段只允许出现在 :: 处）。
    let parse_groups = |part: &str| -> Result<Vec<u16>, String> {
        let mut out = Vec::new();
        if part.is_empty() {
            return Ok(out);
        }
        for g in part.split(':') {
            out.push(parse_v6_group(g, s)?);
        }
        Ok(out)
    };

    let head: Vec<u16>;
    let mut tail: Vec<u16> = Vec::new();
    if let Some(pos) = double_colon {
        head = parse_groups(&main[..pos])?;
        tail = parse_groups(&main[pos + 2..])?;
    } else {
        head = parse_groups(main)?;
    }
    // 内嵌 IPv4 尾段在地址最右端，属于 tail 的末尾。
    tail.extend(v4_groups.iter().copied());

    let fixed = head.len() + tail.len();
    let mut all = head;
    if double_colon.is_some() {
        if fixed > 8 {
            return Err(format!("非法 IPv6（:: 压缩空间不足）: {s}"));
        }
        let zero_count = 8 - fixed;
        all.extend(std::iter::repeat(0u16).take(zero_count));
        all.extend(tail);
    } else if fixed != 8 {
        return Err(format!("非法 IPv6（组数不足且无 ::）: {s}"));
    } else {
        all.extend(tail);
    }

    if all.len() != 8 {
        return Err(format!("非法 IPv6（组数异常）: {s}"));
    }

    let mut value: u128 = 0;
    for g in &all {
        value = (value << 16) | (*g as u128);
    }
    Ok(IpAddr {
        family: Family::V6,
        value,
    })
}


fn parse_v6_group(g: &str, full: &str) -> Result<u16, String> {
    if g.is_empty() {
        return Err(format!("非法 IPv6 空段: {full}"));
    }
    u16::from_str_radix(g, 16).map_err(|_| format!("非法 IPv6 十六进制段: {g} (在 {full} 中)"))
}

fn format_v6(mut v: u128) -> String {
    let mut groups = [0u16; 8];
    for i in (0..8).rev() {
        groups[i] = (v & 0xffff) as u16;
        v >>= 16;
    }
    // RFC5952：找最长全 0 游程（至少 2 组才压缩，平局取最左）。
    let mut best: Option<(usize, usize)> = None; // (start, len)
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len >= 2 {
                match best {
                    None => best = Some((start, len)),
                    Some((_, bl)) if len > bl => best = Some((start, len)),
                    _ => {}
                }
            }
        } else {
            i += 1;
        }
    }
    let hexes: Vec<String> = groups.iter().map(|g| format!("{:x}", g)).collect();
    match best {
        None => hexes.join(":"),
        Some((start, len)) => {
            let left = &hexes[..start];
            let right = &hexes[start + len..];
            format!("{}::{}", left.join(":"), right.join(":"))
        }
    }
}


/// 一个 CIDR 网络（含 iptables 的点分十进制掩码形式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u32,
}

impl IpNet {
    pub fn parse(s: &str) -> Result<IpNet, String> {
        if let Some((addr_part, mask_part)) = s.split_once('/') {
            let addr = IpAddr::parse(addr_part)?;
            let prefix = if mask_part.contains('.') {
                // 点分十进制网络掩码 -> 前缀长度
                let mask = parse_v4(mask_part)?;
                let ones = mask.count_ones();
                if mask != (u32::MAX << (32 - ones)) {
                    return Err(format!("非连续网络掩码: {mask_part}"));
                }
                ones
            } else {
                mask_part
                    .parse::<u32>()
                    .map_err(|_| format!("非法前缀长度: {mask_part}"))?
            };
            if prefix > addr.family.bits() {
                return Err(format!("前缀长度超出协议位数: /{prefix}"));
            }
            Ok(IpNet { addr, prefix })
        } else {
            let addr = IpAddr::parse(s)?;
            Ok(IpNet {
                prefix: addr.family.bits(),
                addr,
            })
        }
    }

    /// 网络起始/结束整数（闭区间）。
    pub fn range(&self) -> (u128, u128) {
        let bits = self.addr.family.bits();
        let host_bits = bits - self.prefix;
        let mask = if host_bits == 0 {
            0u128
        } else if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        let lo = self.addr.value & !mask;
        let hi = lo | mask;
        (lo, hi)
    }

    pub fn family(&self) -> Family {
        self.addr.family
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix == self.addr.family.bits() {
            write!(f, "{}", self.addr.format())
        } else {
            write!(f, "{}/{}", self.addr.format(), self.prefix)
        }
    }
}

/// 把整数按协议族格式化成地址。
pub fn format_ip(family: Family, v: u128) -> String {
    IpAddr {
        family,
        value: v,
    }
    .format()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_ranges_v4() {
        let n = IpNet::parse("192.168.1.0/24").unwrap();
        let (lo, hi) = n.range();
        assert_eq!(lo, IpAddr::parse("192.168.1.0").unwrap().value);
        assert_eq!(hi, IpAddr::parse("192.168.1.255").unwrap().value);
    }

    #[test]
    fn netmask_form() {
        let n = IpNet::parse("10.0.0.0/255.255.255.0").unwrap();
        assert_eq!(n.prefix, 24);
        assert_eq!(n.range(), IpNet::parse("10.0.0.0/24").unwrap().range());
    }

    #[test]
    fn slash_32_and_bare() {
        let a = IpNet::parse("1.2.3.4").unwrap();
        let b = IpNet::parse("1.2.3.4/32").unwrap();
        assert_eq!(a.range(), b.range());
    }

    #[test]
    fn v6_basic_and_compression() {
        let full = IpAddr::parse("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        let short = IpAddr::parse("2001:db8::1").unwrap();
        assert_eq!(full.value, short.value);
        assert_eq!(short.format(), "2001:db8::1");
    }

    #[test]
    fn v6_v4_mapped() {
        let a = IpAddr::parse("::ffff:192.0.2.1").unwrap();
        assert_eq!(a.family, Family::V6);
        assert_eq!(a.format(), "::ffff:c000:201");
    }

    #[test]
    fn v6_cidr() {
        let n = IpNet::parse("2001:db8::/32").unwrap();
        let (lo, hi) = n.range();
        assert_eq!(lo, IpAddr::parse("2001:db8::").unwrap().value);
        assert_eq!(hi, IpAddr::parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").unwrap().value);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn cidr_boundary_precision_v4() {
        // /30 边界：.0-.3，精确到地址
        let n = IpNet::parse("192.168.1.0/30").unwrap();
        let (lo, hi) = n.range();
        assert_eq!(lo, IpAddr::parse("192.168.1.0").unwrap().value);
        assert_eq!(hi, IpAddr::parse("192.168.1.3").unwrap().value);
        // 紧邻的 .4 不在区间
        let outside = IpAddr::parse("192.168.1.4").unwrap().value;
        assert!(outside > hi);
    }

    #[test]
    fn netmask_equivalent_to_cidr() {
        let m = IpNet::parse("172.16.0.0/255.255.0.0").unwrap();
        let c = IpNet::parse("172.16.0.0/16").unwrap();
        assert_eq!(m.range(), c.range());
    }

    #[test]
    fn v6_128_point_and_boundary() {
        let p = IpNet::parse("2001:db8::1/128").unwrap();
        let (lo, hi) = p.range();
        assert_eq!(lo, hi);
        assert_eq!(lo, IpAddr::parse("2001:db8::1").unwrap().value);
        let slash32 = IpNet::parse("2001:db8::/32").unwrap();
        let (l, h) = slash32.range();
        assert_eq!(l, IpAddr::parse("2001:db8::").unwrap().value);
        // 上界最后一个地址
        assert!(lo >= l && lo <= h);
        assert!(IpAddr::parse("2001:db9::1").unwrap().value > h);
    }

    #[test]
    fn v6_roundtrip_formats() {
        for s in ["::1", "::", "2001:db8::1", "fe80::1", "2001:0:0:1::1"] {
            let a = IpAddr::parse(s).unwrap();
            let again = IpAddr::parse(&a.format()).unwrap();
            assert_eq!(a.value, again.value, "roundtrip {s}");
        }
    }
}
