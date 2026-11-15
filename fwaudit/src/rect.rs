//! Exact interval / hyper-rectangle math.
//!
//! A rule's match set is a list of `Rect`s (one per address family, more when
//! set literals expand). Every dimension is an `IntervalSet` over u128 so
//! CIDR complements, intersections and differences are computed exactly.

use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn addr_max(&self) -> u128 {
        match self {
            Family::V4 => u32::MAX as u128,
            Family::V6 => u128::MAX,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Family::V4 => write!(f, "ipv4"),
            Family::V6 => write!(f, "ipv6"),
        }
    }
}

/// Sorted, disjoint, non-adjacent inclusive intervals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalSet {
    pub ivs: Vec<(u128, u128)>,
}

impl IntervalSet {
    pub fn empty() -> Self {
        IntervalSet { ivs: Vec::new() }
    }
    pub fn full(max: u128) -> Self {
        IntervalSet { ivs: vec![(0, max)] }
    }
    pub fn single(lo: u128, hi: u128) -> Self {
        if lo > hi {
            IntervalSet::empty()
        } else {
            IntervalSet { ivs: vec![(lo, hi)] }
        }
    }
    pub fn is_empty(&self) -> bool {
        self.ivs.is_empty()
    }

    pub fn from_unsorted(mut ivs: Vec<(u128, u128)>) -> Self {
        ivs.retain(|(lo, hi)| lo <= hi);
        ivs.sort_unstable();
        let mut out: Vec<(u128, u128)> = Vec::with_capacity(ivs.len());
        for (lo, hi) in ivs {
            if let Some(last) = out.last_mut() {
                // merge overlapping or adjacent (last.1 + 1 >= lo)
                if lo <= last.1.saturating_add(1) {
                    if hi > last.1 {
                        last.1 = hi;
                    }
                    continue;
                }
            }
            out.push((lo, hi));
        }
        IntervalSet { ivs: out }
    }

    pub fn union(sets: &[IntervalSet]) -> Self {
        let mut all = Vec::new();
        for s in sets {
            all.extend_from_slice(&s.ivs);
        }
        IntervalSet::from_unsorted(all)
    }

    pub fn intersect(&self, other: &IntervalSet) -> IntervalSet {
        let mut out = Vec::new();
        let (a, b) = (&self.ivs, &other.ivs);
        let (mut i, mut j) = (0usize, 0usize);
        while i < a.len() && j < b.len() {
            let lo = a[i].0.max(b[j].0);
            let hi = a[i].1.min(b[j].1);
            if lo <= hi {
                out.push((lo, hi));
            }
            if a[i].1 < b[j].1 {
                i += 1;
            } else {
                j += 1;
            }
        }
        IntervalSet { ivs: out }
    }

    /// self \ other
    pub fn subtract(&self, other: &IntervalSet) -> IntervalSet {
        let mut out = Vec::new();
        for &(lo, hi) in &self.ivs {
            let mut cur = lo;
            let mut covered_to_end = false;
            for &(blo, bhi) in &other.ivs {
                if bhi < cur {
                    continue;
                }
                if blo > hi {
                    break;
                }
                if blo > cur {
                    out.push((cur, blo - 1));
                }
                if bhi >= hi {
                    // remainder of this interval is fully covered; using a
                    // flag because hi may be u128::MAX (no cur = hi + 1)
                    covered_to_end = true;
                    break;
                }
                cur = bhi + 1;
            }
            if !covered_to_end && cur <= hi {
                out.push((cur, hi));
            }
        }
        IntervalSet { ivs: out }
    }

    pub fn contains(&self, p: u128) -> bool {
        // small sets: linear is fine, but binary search is cheap
        self.ivs
            .binary_search_by(|&(lo, hi)| {
                if p < lo {
                    std::cmp::Ordering::Greater
                } else if p > hi {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    pub fn subset_of(&self, other: &IntervalSet) -> bool {
        self.subtract(other).is_empty()
    }
}

pub const DIM_SRC: usize = 0;
pub const DIM_DST: usize = 1;
pub const DIM_PROTO: usize = 2;
pub const DIM_SPORT: usize = 3;
pub const DIM_DPORT: usize = 4;
pub const NDIMS: usize = 5;

/// One hyper-rectangle of packet space, single address family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rect {
    pub dims: [IntervalSet; NDIMS],
    pub iif: Option<String>,
    pub oif: Option<String>,
    /// Opaque predicates we cannot model exactly (ct state, tcp flags, ...).
    /// A rect with atoms can only be covered by a rect whose atoms are a
    /// subset; this keeps coverage claims sound.
    pub atoms: BTreeSet<String>,
    pub family: Family,
}

impl Rect {
    pub fn full(family: Family) -> Self {
        let amax = family.addr_max();
        Rect {
            dims: [
                IntervalSet::full(amax),
                IntervalSet::full(amax),
                IntervalSet::full(255),
                IntervalSet::full(65535),
                IntervalSet::full(65535),
            ],
            iif: None,
            oif: None,
            atoms: BTreeSet::new(),
            family,
        }
    }

    /// Intersection; None when disjoint. Symbolic dims must be compatible.
    pub fn intersect(&self, o: &Rect) -> Option<Rect> {
        if self.family != o.family {
            return None;
        }
        if let (Some(a), Some(b)) = (&self.iif, &o.iif) {
            if a != b {
                return None;
            }
        }
        if let (Some(a), Some(b)) = (&self.oif, &o.oif) {
            if a != b {
                return None;
            }
        }
        let mut dims: [IntervalSet; NDIMS] = Default::default();
        for d in 0..NDIMS {
            dims[d] = self.dims[d].intersect(&o.dims[d]);
            if dims[d].is_empty() {
                return None;
            }
        }
        let mut atoms = self.atoms.clone();
        atoms.extend(o.atoms.iter().cloned());
        Some(Rect {
            dims,
            iif: self.iif.clone().or_else(|| o.iif.clone()),
            oif: self.oif.clone().or_else(|| o.oif.clone()),
            atoms,
            family: self.family,
        })
    }

    /// Can `o` shrink `self` at all? (symbolic pre-check)
    fn coverable_by(&self, o: &Rect) -> bool {
        if self.family != o.family {
            return false;
        }
        // o must not be more specific on interfaces than self.
        if let Some(b) = &o.iif {
            if self.iif.as_ref() != Some(b) {
                return false;
            }
        }
        if let Some(b) = &o.oif {
            if self.oif.as_ref() != Some(b) {
                return false;
            }
        }
        // o's opaque predicates must all be present in self.
        o.atoms.iter().all(|a| self.atoms.contains(a))
    }

    /// self \ o. Returns None when o does not overlap self (or cannot be
    /// represented, treated conservatively as "no coverage"). Otherwise the
    /// remaining pieces; an empty Vec means self is fully inside o.
    pub fn subtract(&self, o: &Rect) -> Option<Vec<Rect>> {
        if !self.coverable_by(o) {
            return None;
        }
        self.intersect(o)?; // disjoint -> None
        let mut out: Vec<Rect> = Vec::new();
        let mut rem = self.clone();
        for d in 0..NDIMS {
            let outside = rem.dims[d].subtract(&o.dims[d]);
            for iv in outside.ivs {
                let mut piece = rem.clone();
                piece.dims[d] = IntervalSet { ivs: vec![iv] };
                out.push(piece);
            }
            // guaranteed non-empty because self ∩ o is non-empty
            rem.dims[d] = rem.dims[d].intersect(&o.dims[d]);
        }
        Some(out)
    }

    pub fn contains_point(&self, pt: &[u128; NDIMS]) -> bool {
        (0..NDIMS).all(|d| self.dims[d].contains(pt[d]))
    }
}

impl Default for IntervalSet {
    fn default() -> Self {
        IntervalSet::empty()
    }
}

/// A rule's whole match set: a union of rects.
pub type MatchSet = Vec<Rect>;

/// Subtract `coverer` from every rect in `rem`.
/// Returns (remaining rects, whether anything was subtracted).
/// Gives up (returns None) if the remainder explodes — caller treats as
/// "not covered" and records a warning.
pub fn matchset_subtract(rem: &[Rect], coverer: &[Rect]) -> Option<(Vec<Rect>, bool)> {
    const MAX_RECTS: usize = 64_000;
    let mut hit = false;
    let mut out: Vec<Rect> = Vec::with_capacity(rem.len());
    for r in rem {
        let mut pieces = vec![r.clone()];
        for c in coverer {
            if pieces.is_empty() {
                break;
            }
            let mut next = Vec::with_capacity(pieces.len());
            for p in pieces {
                match p.subtract(c) {
                    Some(ps) => {
                        hit = true;
                        next.extend(ps);
                    }
                    None => next.push(p),
                }
            }
            pieces = next;
            if pieces.len() > MAX_RECTS {
                return None;
            }
        }
        out.extend(pieces);
        if out.len() > MAX_RECTS {
            return None;
        }
    }
    Some((out, hit))
}

/// Remainder of `target` after subtracting every coverer in order.
/// Returns None on complexity blow-up.
pub fn remainder(target: &[Rect], coverers: &[&[Rect]]) -> Option<Vec<Rect>> {
    let mut rem: Vec<Rect> = target.to_vec();
    for c in coverers {
        if rem.is_empty() {
            break;
        }
        rem = matchset_subtract(&rem, c)?.0;
    }
    Some(rem)
}

/// Human-readable rendering of a rect (for conflict regions etc).
pub fn fmt_rect(r: &Rect) -> String {
    let mut parts = Vec::new();
    parts.push(format!("{}", r.family));
    parts.push(format!("src={}", fmt_addr_ivs(&r.dims[DIM_SRC], r.family)));
    parts.push(format!("dst={}", fmt_addr_ivs(&r.dims[DIM_DST], r.family)));
    parts.push(format!("proto={}", fmt_proto_ivs(&r.dims[DIM_PROTO])));
    if r.dims[DIM_SPORT].ivs != [(0, 65535)] {
        parts.push(format!("sport={}", fmt_num_ivs(&r.dims[DIM_SPORT])));
    }
    if r.dims[DIM_DPORT].ivs != [(0, 65535)] {
        parts.push(format!("dport={}", fmt_num_ivs(&r.dims[DIM_DPORT])));
    }
    if let Some(i) = &r.iif {
        parts.push(format!("iif={i}"));
    }
    if let Some(o) = &r.oif {
        parts.push(format!("oif={o}"));
    }
    for a in &r.atoms {
        parts.push(format!("[{a}]"));
    }
    parts.join(" ")
}

pub fn fmt_addr_ivs(s: &IntervalSet, fam: Family) -> String {
    if s.ivs == [(0, fam.addr_max())] {
        return "any".into();
    }
    s.ivs
        .iter()
        .map(|&(lo, hi)| fmt_addr_range(lo, hi, fam))
        .collect::<Vec<_>>()
        .join(",")
}

fn fmt_addr_range(lo: u128, hi: u128, fam: Family) -> String {
    // try to render as CIDR when it is exactly one prefix
    if let Some(cidr) = range_as_cidr(lo, hi, fam) {
        return cidr;
    }
    format!("{}-{}", fmt_ip(lo, fam), fmt_ip(hi, fam))
}

fn range_as_cidr(lo: u128, hi: u128, fam: Family) -> Option<String> {
    let bits = match fam {
        Family::V4 => 32,
        Family::V6 => 128,
    };
    let size = hi.wrapping_sub(lo).wrapping_add(1); // power of two iff aligned block
    if size == 0 || !size.is_power_of_two() {
        return None;
    }
    let len = bits - size.trailing_zeros() as usize;
    if lo % size != 0 {
        return None;
    }
    Some(format!("{}/{}", fmt_ip(lo, fam), len))
}

pub fn fmt_ip(v: u128, fam: Family) -> String {
    match fam {
        Family::V4 => {
            let v = v as u32;
            format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255)
        }
        Family::V6 => {
            let b = v.to_be_bytes();
            let mut groups = [0u16; 8];
            for i in 0..8 {
                groups[i] = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
            }
            // find longest zero run
            let (mut best_start, mut best_len) = (usize::MAX, 0usize);
            let mut i = 0;
            while i < 8 {
                if groups[i] == 0 {
                    let start = i;
                    while i < 8 && groups[i] == 0 {
                        i += 1;
                    }
                    if i - start > best_len {
                        best_start = start;
                        best_len = i - start;
                    }
                } else {
                    i += 1;
                }
            }
            if best_len < 2 {
                best_start = usize::MAX;
            }
            let mut s = String::new();
            let mut i = 0;
            while i < 8 {
                if i == best_start {
                    s.push_str("::");
                    i += best_len;
                    continue;
                }
                if !s.is_empty() && !s.ends_with(':') {
                    s.push(':');
                }
                s.push_str(&format!("{:x}", groups[i]));
                i += 1;
            }
            if s.is_empty() {
                s.push_str("::");
            }
            s
        }
    }
}

pub fn fmt_num_ivs(s: &IntervalSet) -> String {
    if s.ivs == [(0, 65535)] {
        return "any".into();
    }
    s.ivs
        .iter()
        .map(|&(lo, hi)| {
            if lo == hi {
                format!("{lo}")
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn fmt_proto_ivs(s: &IntervalSet) -> String {
    if s.ivs == [(0, 255)] {
        return "any".into();
    }
    s.ivs
        .iter()
        .map(|&(lo, hi)| {
            if lo == hi {
                proto_name(lo as u8).to_string()
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn proto_name(n: u8) -> &'static str {
    match n {
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "icmpv6",
        89 => "ospf",
        132 => "sctp",
        136 => "udplite",
        _ => "",
    }
}

pub fn proto_display(n: u8) -> String {
    let name = proto_name(n);
    if name.is_empty() {
        format!("{n}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(v: &[(u128, u128)]) -> IntervalSet {
        IntervalSet::from_unsorted(v.to_vec())
    }

    #[test]
    fn test_normalize_merges_adjacent() {
        let s = iv(&[(10, 20), (0, 5), (6, 9), (30, 40), (21, 25)]);
        assert_eq!(s.ivs, vec![(0, 25), (30, 40)]);
    }

    #[test]
    fn test_subtract_basic() {
        let a = iv(&[(0, 100)]);
        let b = iv(&[(10, 20)]);
        assert_eq!(a.subtract(&b).ivs, vec![(0, 9), (21, 100)]);
    }

    #[test]
    fn test_subtract_edges() {
        let a = iv(&[(0, 100)]);
        assert_eq!(a.subtract(&iv(&[(0, 50)])).ivs, vec![(51, 100)]);
        assert_eq!(a.subtract(&iv(&[(50, 100)])).ivs, vec![(0, 49)]);
        assert!(a.subtract(&iv(&[(0, 100)])).is_empty());
        assert!(a.subtract(&iv(&[(0, u128::MAX)])).is_empty());
        assert_eq!(a.subtract(&iv(&[(200, 300)])).ivs, vec![(0, 100)]);
    }

    #[test]
    fn test_subtract_u128_max_boundary() {
        // full space minus full space must be empty (regression: saturating
        // add at u128::MAX left a phantom (MAX, MAX) point)
        let full = IntervalSet::full(u128::MAX);
        assert!(full.subtract(&full).is_empty());
        // full minus a middle block
        let r = full.subtract(&iv(&[(10, 20)]));
        assert_eq!(r.ivs, vec![(0, 9), (21, u128::MAX)]);
        // full minus a block touching the top
        let r = full.subtract(&iv(&[(100, u128::MAX)]));
        assert_eq!(r.ivs, vec![(0, 99)]);
        // point at the very top
        let r = full.subtract(&iv(&[(u128::MAX, u128::MAX)]));
        assert_eq!(r.ivs, vec![(0, u128::MAX - 1)]);
    }

    #[test]
    fn test_subtract_multi() {
        let a = iv(&[(0, 10), (20, 30)]);
        let b = iv(&[(5, 25)]);
        assert_eq!(a.subtract(&b).ivs, vec![(0, 4), (26, 30)]);
    }

    #[test]
    fn test_intersect() {
        let a = iv(&[(0, 10), (20, 30)]);
        let b = iv(&[(5, 25)]);
        assert_eq!(a.intersect(&b).ivs, vec![(5, 10), (20, 25)]);
    }

    #[test]
    fn test_rect_subtract_full_cover() {
        let a = Rect::full(Family::V4);
        let b = Rect::full(Family::V4);
        assert_eq!(a.subtract(&b), Some(vec![]));
    }

    #[test]
    fn test_rect_subtract_disjoint() {
        let mut a = Rect::full(Family::V4);
        a.dims[DIM_SRC] = IntervalSet::single(10, 20);
        let mut b = Rect::full(Family::V4);
        b.dims[DIM_SRC] = IntervalSet::single(30, 40);
        assert_eq!(a.subtract(&b), None);
    }

    #[test]
    fn test_rect_subtract_splits() {
        // a: src 0-99; b: src 10-19, dport 80
        let mut a = Rect::full(Family::V4);
        a.dims[DIM_SRC] = IntervalSet::single(0, 99);
        let mut b = Rect::full(Family::V4);
        b.dims[DIM_SRC] = IntervalSet::single(10, 19);
        b.dims[DIM_DPORT] = IntervalSet::single(80, 80);
        let pieces = a.subtract(&b).unwrap();
        // expect: src 0-9 (any dport), src 20-99 (any dport),
        //         src 10-19 dport 0-79, src 10-19 dport 81-65535
        let mut found = 0;
        for p in &pieces {
            if p.dims[DIM_SRC].ivs == [(0, 9)] || p.dims[DIM_SRC].ivs == [(20, 99)] {
                assert_eq!(p.dims[DIM_DPORT].ivs, [(0, 65535)]);
                found += 1;
            }
            if p.dims[DIM_SRC].ivs == [(10, 19)]
                && (p.dims[DIM_DPORT].ivs == [(0, 79)] || p.dims[DIM_DPORT].ivs == [(81, 65535)])
            {
                found += 1;
            }
        }
        assert_eq!(found, 4);
        assert_eq!(pieces.len(), 4);
    }

    #[test]
    fn test_rect_atoms_block_coverage() {
        let mut a = Rect::full(Family::V4);
        a.atoms.insert("ct state established".into());
        let b = Rect::full(Family::V4); // no atoms: matches a superset -> CAN cover a
        assert_eq!(a.subtract(&b), Some(vec![]));
        // a is more specific (requires ct state) -> cannot cover the wider b
        assert_eq!(b.subtract(&a), None);
    }

    #[test]
    fn test_rect_iif() {
        let mut a = Rect::full(Family::V4);
        a.iif = Some("eth0".into());
        let mut b = Rect::full(Family::V4);
        b.iif = Some("eth0".into());
        assert_eq!(a.subtract(&b), Some(vec![]));
        b.iif = Some("eth1".into());
        assert_eq!(a.subtract(&b), None);
        // unconstrained self cannot be covered by constrained b
        let plain = Rect::full(Family::V4);
        let mut c = Rect::full(Family::V4);
        c.iif = Some("eth0".into());
        assert_eq!(plain.subtract(&c), None);
        // constrained self IS covered by unconstrained b
        assert_eq!(a.subtract(&Rect::full(Family::V4)), Some(vec![]));
    }

    #[test]
    fn test_family_mismatch() {
        let a = Rect::full(Family::V4);
        let b = Rect::full(Family::V6);
        assert_eq!(a.subtract(&b), None);
        assert!(a.intersect(&b).is_none());
    }

    #[test]
    fn test_cidr_fmt() {
        assert_eq!(range_as_cidr(0x0A000000, 0x0AFFFFFF, Family::V4), Some("10.0.0.0/8".into()));
        assert_eq!(range_as_cidr(0, u32::MAX as u128, Family::V4), Some("0.0.0.0/0".into()));
        assert_eq!(range_as_cidr(1, 2, Family::V4), None);
    }
}
