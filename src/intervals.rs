//! 整数区间集合：闭区间 [lo, hi] 的有序并集，全部运算精确（不抽样）。

/// 一组互不相交、已排序、相邻即合并的闭区间。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntervalSet {
    ranges: Vec<(u128, u128)>,
}

impl IntervalSet {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn point(v: u128) -> Self {
        Self { ranges: vec![(v, v)] }
    }

    pub fn range(lo: u128, hi: u128) -> Self {
        assert!(lo <= hi);
        Self { ranges: vec![(lo, hi)] }
    }

    pub fn universe(hi: u128) -> Self {
        Self { ranges: vec![(0, hi)] }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[(u128, u128)] {
        &self.ranges
    }

    pub fn min(&self) -> Option<u128> {
        self.ranges.first().map(|(lo, _)| *lo)
    }

    pub fn max(&self) -> Option<u128> {
        self.ranges.last().map(|(_, hi)| *hi)
    }

    pub fn contains(&self, v: u128) -> bool {
        self.ranges.binary_search_by(|(lo, hi)| {
            if v < *lo {
                std::cmp::Ordering::Greater
            } else if v > *hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).is_ok()
    }

    /// 精确并集。
    pub fn union(&self, other: &Self) -> Self {
        let mut all = self.ranges.clone();
        all.extend_from_slice(&other.ranges);
        all.sort_unstable_by_key(|(lo, _)| *lo);
        let mut out: Vec<(u128, u128)> = Vec::with_capacity(all.len());
        for (lo, hi) in all {
            if let Some(last) = out.last_mut() {
                if lo <= last.1.saturating_add(1) {
                    if hi > last.1 {
                        last.1 = hi;
                    }
                    continue;
                }
            }
            out.push((lo, hi));
        }
        Self { ranges: out }
    }

    /// 精确交集。
    pub fn intersect(&self, other: &Self) -> Self {
        let mut out = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a_lo, a_hi) = self.ranges[i];
            let (b_lo, b_hi) = other.ranges[j];
            let lo = a_lo.max(b_lo);
            let hi = a_hi.min(b_hi);
            if lo <= hi {
                out.push((lo, hi));
            }
            if a_hi < b_hi {
                i += 1;
            } else {
                j += 1;
            }
        }
        Self { ranges: out }
    }

    /// 精确差集 self - other。
    pub fn subtract(&self, other: &Self) -> Self {
        let mut out = self.ranges.clone();
        for &(blo, bhi) in &other.ranges {
            let mut next = Vec::with_capacity(out.len() + 1);
            for (lo, hi) in out {
                if bhi < lo || blo > hi {
                    next.push((lo, hi));
                } else {
                    if blo > lo {
                        next.push((lo, blo - 1));
                    }
                    if bhi < hi {
                        next.push((bhi + 1, hi));
                    }
                }
            }
            out = next;
        }
        Self { ranges: out }
    }

    /// self 是否为 other 的子集（self ⊆ other）。
    pub fn is_subset_of(&self, other: &Self) -> bool {
        if self.ranges.is_empty() {
            return true;
        }
        let mut j = 0usize;
        for &(lo, hi) in &self.ranges {
            // 找到可能覆盖 lo 的 other 区间
            while j < other.ranges.len() && other.ranges[j].1 < lo {
                j += 1;
            }
            match other.ranges.get(j) {
                Some(&(olo, ohi)) if olo <= lo && hi <= ohi => {}
                _ => return false,
            }
        }
        true
    }

    /// 把区间格式化成人类可读的离散值列表/区间描述。
    /// `fmt` 把整数转成具体含义（IP 地址 / 端口号 / 协议名）。
    pub fn describe<F: Fn(u128) -> String>(&self, fmt: F) -> Vec<String> {
        self.ranges
            .iter()
            .map(|&(lo, hi)| {
                if lo == hi {
                    fmt(lo)
                } else {
                    format!("{}-{}", fmt(lo), fmt(hi))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_merges_adjacent() {
        let a = IntervalSet::range(1, 3);
        let b = IntervalSet::range(4, 5);
        assert_eq!(a.union(&b), IntervalSet::range(1, 5));
    }

    #[test]
    fn subtraction_splits() {
        let u = IntervalSet::range(0, 10);
        let m = IntervalSet::range(3, 7);
        let d = u.subtract(&m);
        assert_eq!(d.ranges(), &[(0, 2), (8, 10)]);
    }

    #[test]
    fn subset_and_intersect() {
        let u = IntervalSet::range(0, 100);
        let s = IntervalSet::range(10, 20).union(&IntervalSet::range(30, 40));
        assert!(s.is_subset_of(&u));
        assert!(!u.is_subset_of(&s));
        assert_eq!(s.intersect(&IntervalSet::range(15, 35)).ranges(),
                   &[(15, 20), (30, 35)]);
    }

    #[test]
    fn empty_subset_of_anything() {
        assert!(IntervalSet::new().is_subset_of(&IntervalSet::new()));
        assert!(IntervalSet::new().is_subset_of(&IntervalSet::point(1)));
    }
}
