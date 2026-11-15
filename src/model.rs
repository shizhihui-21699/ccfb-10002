//! 内部数据模型：规则、链、表、判定动作，以及规则匹配空间的精确集合表示。

use crate::intervals::IntervalSet;
use crate::ip::Family;
use std::fmt;

/// 规则在规则集中的稳定标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId {
    pub table: String,
    pub chain: String,
    /// 链内序号，从 0 开始。
    pub index: usize,
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}#{}", self.table, self.chain, self.index)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Accept,
    Drop,
    Reject,
    Queue,
    Return,
    Jump,
    Goto,
    /// 无法解析的动作，按非终结、不遮蔽处理。
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub kind: VerdictKind,
    /// Jump/Goto 的目标链名。
    pub target: Option<String>,
    /// REJECT 的拒绝方式（仅展示用）。
    pub detail: Option<String>,
    /// 原始动作文本。
    pub raw: String,
}

impl Verdict {
    pub fn is_terminal_here(&self) -> bool {
        // 在当前链内终结遍历：显式判定与 Goto（不返回本链）。
        // Jump 是否终结取决于目标链是否必然终结，分析阶段另行计算。
        matches!(
            self.kind,
            VerdictKind::Accept
                | VerdictKind::Drop
                | VerdictKind::Reject
                | VerdictKind::Queue
                | VerdictKind::Goto
        )
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// 接口名匹配的一个“原子”：包含若干模式，减去若干模式。
/// 模式均为精确名或以 `+`/`*` 结尾的前缀（如 `eth+`、`eth0`）。
/// 空模式串表示通配（匹配任意接口名，含空名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceAtom {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl IfaceAtom {
    pub fn any() -> Self {
        IfaceAtom {
            include: vec![String::new()],
            exclude: vec![],
        }
    }

    pub fn matches_name(&self, name: &str) -> bool {
        self.include.iter().any(|p| pat_matches(p, name))
            && !self.exclude.iter().any(|p| pat_matches(p, name))
    }
}

pub fn pat_matches(pat: &str, name: &str) -> bool {
    if pat.is_empty() {
        return true;
    }
    match pat.strip_suffix(['+', '*']) {
        Some(prefix) => name.starts_with(prefix),
        None => name == pat,
    }
}

/// 接口谓词：DNF（原子的并集）。空 DNF = 空集；单原子 `any()` = 全集。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfacePred {
    pub atoms: Vec<IfaceAtom>,
}

impl IfacePred {
    pub fn universe() -> Self {
        IfacePred {
            atoms: vec![IfaceAtom::any()],
        }
    }

    pub fn is_empty_pred(&self) -> bool {
        self.atoms.is_empty()
    }

    pub fn is_universe(&self) -> bool {
        // 全集的规范形式是单 any 原子；运算结果中也可能出现覆盖全域的其它形式，
        // 这里做保守判断（分析的包含关系走 is_subset_of，不依赖本方法）。
        self.atoms.len() == 1 && self.atoms[0].include == vec![String::new()] && self.atoms[0].exclude.is_empty()
    }

    pub fn from_pat(pat: String, negated: bool) -> Self {
        let atom = if negated {
            IfaceAtom {
                include: vec![String::new()],
                exclude: vec![pat],
            }
        } else {
            IfaceAtom {
                include: vec![pat],
                exclude: vec![],
            }
        };
        IfacePred { atoms: vec![atom] }
    }

    pub fn matches_name(&self, name: &str) -> bool {
        self.atoms.iter().any(|a| a.matches_name(name))
    }

    /// 两个模式是否相交（存在公共字符串）。
    fn pat_intersects(a: &str, b: &str) -> bool {
        let ap = a.strip_suffix(['+', '*']).unwrap_or(a);
        let bp = b.strip_suffix(['+', '*']).unwrap_or(b);
        let a_prefix = a.ends_with(['+', '*']) || a.is_empty();
        let b_prefix = b.ends_with(['+', '*']) || b.is_empty();
        match (a_prefix, b_prefix) {
            (true, true) => true, // 两个前缀（含通配）总有公共串
            (true, false) => bp.starts_with(ap),
            (false, true) => ap.starts_with(bp),
            (false, false) => a == b,
        }
    }

    /// 模式 a 是否为模式 b 的子集（凡匹配 a 的名字都匹配 b）。
    fn pat_subset(a: &str, b: &str) -> bool {
        if b.is_empty() {
            return true;
        }
        let ap = a.strip_suffix(['+', '*']).unwrap_or(a);
        let bp = b.strip_suffix(['+', '*']).unwrap_or(b);
        let b_prefix = b.ends_with(['+', '*']);
        if b_prefix {
            ap.starts_with(bp)
        } else if a.ends_with(['+', '*']) {
            false // 前缀不可能是精确名的子集
        } else {
            a == b
        }
    }

    /// self ⊆ other？
    pub fn is_subset_of(&self, other: &IfacePred) -> bool {
        if self.atoms.is_empty() {
            return true;
        }
        self.atoms.iter().all(|a| atom_subset(a, other))
    }

    pub fn intersects(&self, other: &IfacePred) -> bool {
        self.atoms
            .iter()
            .any(|a| other.atoms.iter().any(|b| atom_intersects(a, b)))
    }

    /// 精确交集（DNF 展开）。
    pub fn intersect(&self, other: &IfacePred) -> IfacePred {
        let mut atoms = Vec::new();
        for a in &self.atoms {
            for b in &other.atoms {
                if let Some(c) = atom_intersect(a, b) {
                    atoms.push(c);
                }
            }
        }
        let mut p = IfacePred { atoms };
        p.simplify();
        p
    }

    /// self - other。
    pub fn subtract(&self, other: &IfacePred) -> IfacePred {
        let mut atoms = Vec::new();
        for a in &self.atoms {
            atoms.extend(atom_subtract(a, other));
        }
        let mut p = IfacePred { atoms };
        p.simplify();
        p
    }

    /// 去掉被其它原子包含的原子，控制 DNF 体积。
    fn simplify(&mut self) {
        let mut keep = vec![true; self.atoms.len()];
        for i in 0..self.atoms.len() {
            if !keep[i] {
                continue;
            }
            for j in 0..self.atoms.len() {
                if i == j || !keep[j] {
                    continue;
                }
                // i ⊆ j 则 i 冗余
                if atom_subset(&self.atoms[i], &IfacePred {
                    atoms: vec![self.atoms[j].clone()],
                }) {
                    keep[i] = false;
                    break;
                }
            }
        }
        let mut atoms: Vec<IfaceAtom> = self
            .atoms
            .drain(..)
            .enumerate()
            .filter(|(i, _)| keep[*i])
            .map(|(_, a)| a)
            .collect();
        // 同 include 合并 exclude
        atoms.sort_by(|a, b| a.include.cmp(&b.include));
        atoms.dedup();
        self.atoms = atoms;
    }

    pub fn describe(&self) -> String {
        if self.atoms.is_empty() {
            return "∅".to_string();
        }
        self.atoms
            .iter()
            .map(|a| {
                let inc = a
                    .include
                    .iter()
                    .map(|p| if p.is_empty() { "*" } else { p.as_str() })
                    .collect::<Vec<_>>()
                    .join(",");
                if a.exclude.is_empty() {
                    inc
                } else {
                    format!("{inc}!{}", a.exclude.join(","))
                }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

fn atom_subset(a: &IfaceAtom, pred: &IfacePred) -> bool {
    // a 中任意满足的名字必须落在 pred 某个原子里。
    // 保守做法：对 pred 做 a 的差集，非空即不子集。接口域为有限字符串集，
    // 这里用模式级精确判定。
    let diff = atom_subtract(a, pred);
    diff.is_empty()
}

fn atom_intersects(a: &IfaceAtom, b: &IfaceAtom) -> bool {
    atom_intersect(a, b).is_some()
}

/// 两个原子的交集：include 两两求交，再减去双方 exclude。
fn atom_intersect(a: &IfaceAtom, b: &IfaceAtom) -> Option<IfaceAtom> {
    let mut include = Vec::new();
    for pa in &a.include {
        for pb in &b.include {
            if let Some(p) = pat_meet(pa, pb) {
                include.push(p);
            }
        }
    }
    if include.is_empty() {
        return None;
    }
    let mut exclude = a.exclude.clone();
    exclude.extend(b.exclude.iter().cloned());
    // 若某个 exclude 已包含整个 include，原子为空
    for ex in &exclude {
        if include.iter().all(|p| IfacePred::pat_subset(p, ex)) {
            return None;
        }
    }
    Some(IfaceAtom { include, exclude })
}

/// 两个模式的交（取更“窄”的模式；无交返回 None）。
fn pat_meet(a: &str, b: &str) -> Option<String> {
    if !IfacePred::pat_intersects(a, b) {
        return None;
    }
    if IfacePred::pat_subset(a, b) {
        Some(a.to_string())
    } else if IfacePred::pat_subset(b, a) {
        Some(b.to_string())
    } else {
        // 两个相交前缀但互不为子集：取更长的前缀（它属于两者交集）
        let ap = a.strip_suffix(['+', '*']).unwrap_or(a);
        let bp = b.strip_suffix(['+', '*']).unwrap_or(b);
        if ap.len() >= bp.len() {
            Some(a.to_string())
        } else {
            Some(b.to_string())
        }
    }
}

/// a - pred：返回若干原子。
fn atom_subtract(a: &IfaceAtom, pred: &IfacePred) -> Vec<IfaceAtom> {
    // 逐原子减去 pred 中与 a 相交的原子；每次减法通过追加 exclude 实现。
    let mut current = vec![a.clone()];
    for b in &pred.atoms {
        let mut next = Vec::new();
        for c in &current {
            if let Some(meet) = atom_intersect(c, b) {
                // 被减去的部分 = meet；用 meet 的 include 模式作为 exclude。
                let mut minus = c.clone();
                for p in &meet.include {
                    if !minus.exclude.contains(p) {
                        minus.exclude.push(p.clone());
                    }
                }
                // 若 exclude 吞掉全部 include，则该原子消失
                let swallowed = minus
                    .include
                    .iter()
                    .all(|p| minus.exclude.iter().any(|e| IfacePred::pat_subset(p, e)));
                if !swallowed {
                    next.push(minus);
                }
            } else {
                next.push(c.clone());
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
}

/// 连接跟踪状态（离散域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState {
    New = 0,
    Established = 1,
    Related = 2,
    Untracked = 3,
    Invalid = 4,
}

pub fn parse_conn_state(s: &str) -> Option<ConnState> {
    Some(match s.to_ascii_uppercase().as_str() {
        "NEW" => ConnState::New,
        "ESTABLISHED" => ConnState::Established,
        "RELATED" => ConnState::Related,
        "UNTRACKED" => ConnState::Untracked,
        "INVALID" => ConnState::Invalid,
        _ => return None,
    })
}

pub fn conn_state_name(s: ConnState) -> &'static str {
    match s {
        ConnState::New => "NEW",
        ConnState::Established => "ESTABLISHED",
        ConnState::Related => "RELATED",
        ConnState::Untracked => "UNTRACKED",
        ConnState::Invalid => "INVALID",
    }
}

/// 一条规则的匹配空间。每个数值字段都是区间集合；
/// “未约束”用整个协议域的全集表示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSet {
    pub family: Family,
    pub src_ip: IntervalSet,
    pub dst_ip: IntervalSet,
    pub proto: IntervalSet,
    pub src_port: IntervalSet,
    pub dst_port: IntervalSet,
    pub icmp_type: IntervalSet,
    pub state: IntervalSet,
    pub iif: IfacePred,
    pub oif: IfacePred,
}

impl MatchSet {
    /// 协议域全集。
    pub fn universe(family: Family) -> Self {
        MatchSet {
            family,
            src_ip: IntervalSet::universe(family.max_value()),
            dst_ip: IntervalSet::universe(family.max_value()),
            proto: IntervalSet::universe(255),
            src_port: IntervalSet::universe(65535),
            dst_port: IntervalSet::universe(65535),
            icmp_type: IntervalSet::universe(255),
            state: IntervalSet::universe(4),
            iif: IfacePred::universe(),
            oif: IfacePred::universe(),
        }
    }

    /// 不可能匹配任何报文（矛盾条件）。
    pub fn empty(family: Family) -> Self {
        MatchSet {
            family,
            src_ip: IntervalSet::new(),
            dst_ip: IntervalSet::new(),
            proto: IntervalSet::new(),
            src_port: IntervalSet::new(),
            dst_port: IntervalSet::new(),
            icmp_type: IntervalSet::new(),
            state: IntervalSet::new(),
            iif: IfacePred::default(),
            oif: IfacePred::default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.src_ip.is_empty()
            || self.dst_ip.is_empty()
            || self.proto.is_empty()
            || self.src_port.is_empty()
            || self.dst_port.is_empty()
            || self.icmp_type.is_empty()
            || self.state.is_empty()
            || self.iif.is_empty_pred()
            || self.oif.is_empty_pred()
    }

    /// 精确交集（逐字段）。
    pub fn intersect(&self, other: &MatchSet) -> MatchSet {
        let fam = self.family;
        MatchSet {
            family: fam,
            src_ip: self.src_ip.intersect(&other.src_ip),
            dst_ip: self.dst_ip.intersect(&other.dst_ip),
            proto: self.proto.intersect(&other.proto),
            src_port: self.src_port.intersect(&other.src_port),
            dst_port: self.dst_port.intersect(&other.dst_port),
            icmp_type: self.icmp_type.intersect(&other.icmp_type),
            state: self.state.intersect(&other.state),
            iif: self.iif.intersect(&other.iif),
            oif: self.oif.intersect(&other.oif),
        }
    }

    /// self ⊆ other？逐字段判定。
    pub fn is_subset_of(&self, other: &MatchSet) -> bool {
        self.src_ip.is_subset_of(&other.src_ip)
            && self.dst_ip.is_subset_of(&other.dst_ip)
            && self.proto.is_subset_of(&other.proto)
            && self.src_port.is_subset_of(&other.src_port)
            && self.dst_port.is_subset_of(&other.dst_port)
            && self.icmp_type.is_subset_of(&other.icmp_type)
            && self.state.is_subset_of(&other.state)
            && self.iif.is_subset_of(&other.iif)
            && self.oif.is_subset_of(&other.oif)
    }

    /// 精确差集 self - other（逐字段；接口域走 DNF 减法）。
    pub fn subtract(&self, other: &MatchSet) -> Vec<MatchSet> {
        // 多字段差集展开为“某字段被挖空一块”的并集，逐字段生成。
        let base = self.clone();
        let mut pieces: Vec<MatchSet> = Vec::new();

        let mut push = |field: &str, narrowed: IntervalSet, cur: &MatchSet| {
            if narrowed.is_empty() {
                return;
            }
            let mut m = cur.clone();
            match field {
                "src_ip" => m.src_ip = narrowed,
                "dst_ip" => m.dst_ip = narrowed,
                "proto" => m.proto = narrowed,
                "src_port" => m.src_port = narrowed,
                "dst_port" => m.dst_port = narrowed,
                "icmp_type" => m.icmp_type = narrowed,
                "state" => m.state = narrowed,
                _ => unreachable!(),
            }
            pieces.push(m);
        };

        // 数值字段：依次切分，保持互斥
        let mut remaining = base.clone();
        for field in [
            "src_ip",
            "dst_ip",
            "proto",
            "src_port",
            "dst_port",
            "icmp_type",
            "state",
        ] {
            let cur = match field {
                "src_ip" => &remaining.src_ip,
                "dst_ip" => &remaining.dst_ip,
                "proto" => &remaining.proto,
                "src_port" => &remaining.src_port,
                "dst_port" => &remaining.dst_port,
                "icmp_type" => &remaining.icmp_type,
                "state" => &remaining.state,
                _ => unreachable!(),
            };
            let other_set = match field {
                "src_ip" => &other.src_ip,
                "dst_ip" => &other.dst_ip,
                "proto" => &other.proto,
                "src_port" => &other.src_port,
                "dst_port" => &other.dst_port,
                "icmp_type" => &other.icmp_type,
                "state" => &other.state,
                _ => unreachable!(),
            };
            let diff = cur.subtract(other_set);
            if !diff.is_empty() {
                push(field, diff, &remaining);
            }
            // remaining 在该字段上收敛为交集
            match field {
                "src_ip" => remaining.src_ip = cur.intersect(other_set),
                "dst_ip" => remaining.dst_ip = cur.intersect(other_set),
                "proto" => remaining.proto = cur.intersect(other_set),
                "src_port" => remaining.src_port = cur.intersect(other_set),
                "dst_port" => remaining.dst_port = cur.intersect(other_set),
                "icmp_type" => remaining.icmp_type = cur.intersect(other_set),
                "state" => remaining.state = cur.intersect(other_set),
                _ => unreachable!(),
            }
        }

        // 接口字段：DNF 差集
        let iif_diff = remaining.iif.subtract(&other.iif);
        if !iif_diff.is_empty_pred() {
            let mut m = remaining.clone();
            m.iif = iif_diff;
            pieces.push(m);
        }
        let mut after_iif = remaining.clone();
        after_iif.iif = after_iif.iif.intersect(&other.iif);

        let oif_diff = after_iif.oif.subtract(&other.oif);
        if !oif_diff.is_empty_pred() {
            let mut m = after_iif.clone();
            m.oif = oif_diff;
            pieces.push(m);
        }

        pieces
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: RuleId,
    pub file: String,
    pub line_no: usize,
    pub raw: String,
    pub matches: MatchSet,
    pub verdict: Verdict,
    /// 解析阶段无法精确建模、按“匹配所有”保守处理的选项。
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Chain {
    pub name: String,
    /// 基础链的默认策略（ACCEPT/DROP/...），自定义链为 None。
    pub policy: Option<String>,
    /// iptables 内置链的包/字节计数（nft 为 0）。
    pub counters: (u64, u64),
    /// nft 基础链 hook 与优先级（展示用）。
    pub hook: Option<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Default)]
pub struct Table {
    pub name: String,
    pub family: Family,
    pub chains: Vec<Chain>,
}

impl Table {
    pub fn chain(&self, name: &str) -> Option<&Chain> {
        self.chains.iter().find(|c| c.name == name)
    }
    pub fn chain_mut(&mut self, name: &str) -> Option<&mut Chain> {
        self.chains.iter_mut().find(|c| c.name == name)
    }
}

/// 解析后的完整规则集。同协议族的表分别存放，不跨族比较。
#[derive(Debug, Clone, Default)]
pub struct Ruleset {
    pub tables: Vec<Table>,
    /// 解析告警（不致命）。
    pub warnings: Vec<String>,
}

impl Ruleset {
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }
    pub fn table_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.tables.iter_mut().find(|t| t.name == name)
    }
    pub fn get_rule(&self, id: &RuleId) -> Option<&Rule> {
        self.table(&id.table)
            .and_then(|t| t.chain(&id.chain))
            .and_then(|c| c.rules.get(id.index))
    }
}

#[cfg(test)]
mod iface_tests {
    use super::*;

    #[test]
    fn iface_prefix_and_negation() {
        let eth = IfacePred::from_pat("eth+".into(), false);
        assert!(eth.matches_name("eth0"));
        assert!(eth.matches_name("eth10"));
        assert!(!eth.matches_name("wlan0"));

        let not_eth0 = IfacePred::from_pat("eth0".into(), true);
        assert!(not_eth0.matches_name("eth1"));
        assert!(!not_eth0.matches_name("eth0"));
        assert!(not_eth0.matches_name("wlan0"));
    }

    #[test]
    fn iface_subset_and_intersect() {
        let eth0 = IfacePred::from_pat("eth0".into(), false);
        let eth = IfacePred::from_pat("eth+".into(), false);
        assert!(eth0.is_subset_of(&eth));
        assert!(!eth.is_subset_of(&eth0));
        assert!(eth0.intersects(&eth));
        let wlan = IfacePred::from_pat("wlan+".into(), false);
        assert!(!eth0.intersects(&wlan));
    }

    #[test]
    fn iface_subtraction_leaves_other_names() {
        let any = IfacePred::universe();
        let eth0 = IfacePred::from_pat("eth0".into(), false);
        let rest = any.subtract(&eth0);
        // eth0 被挖掉，其它名字仍在
        assert!(!rest.matches_name("eth0"));
        assert!(rest.matches_name("eth1"));
        assert!(rest.matches_name("wlan0"));
    }
}
