//! 规则分析引擎。
//!
//! 三类问题的精确定义（同一链内，按规则顺序）：
//!
//! * 遮蔽（shadowed）：规则 r 的匹配空间在扣除它之前所有“终结规则”覆盖的部分后
//!   为空 —— 任何能命中 r 的报文都已在前面被终结，r 永远不会被求值。
//!   终结规则指 ACCEPT/DROP/REJECT/QUEUE/Goto，以及目标链“必然终结”的 Jump。
//!   支持多规则联合遮蔽：单条盖不住时，用精确集合差集逐条扣减，差集为空即遮蔽。
//!
//! * 冗余（redundant）：匹配空间为空（条件自相矛盾），或与前面某条规则的匹配空间
//!   完全相同（相同空间下后出现的规则不可能产生新行为，与动作无关）。
//!
//! * 冲突（conflict）：两条规则匹配空间有交集，但在交集上的最终动作不同
//!   （不同判定，或跳往不同链）。交集按字段精确给出。

use crate::model::*;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ShadowFinding {
    pub rule: RuleId,
    /// 单独一条就完成遮蔽的规则（若存在）。
    pub by_single: Option<RuleId>,
    /// 按链内顺序参与联合遮蔽的规则序列。
    pub by_combination: Vec<RuleId>,
}

#[derive(Debug, Clone)]
pub struct RedundantFinding {
    pub rule: RuleId,
    pub reason: RedundantReason,
}

#[derive(Debug, Clone)]
pub enum RedundantReason {
    EmptyMatch,
    DuplicateOf(RuleId),
}

#[derive(Debug, Clone)]
pub struct ConflictFinding {
    pub first: RuleId,
    pub second: RuleId,
    /// 两规则匹配空间的精确交集（用于展示冲突覆盖的报文范围）。
    pub intersection: MatchSet,
}

#[derive(Debug, Clone, Default)]
pub struct ChainReport {
    pub table: String,
    pub chain: String,
    pub shadowed: Vec<ShadowFinding>,
    pub redundant: Vec<RedundantFinding>,
    pub conflicts: Vec<ConflictFinding>,
    /// 链不可达（没有任何基础链路径能跳到它）。
    pub unreachable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisReport {
    pub chains: Vec<ChainReport>,
    /// 表 -> 链名 -> 是否“必然终结”。
    pub always_terminal: HashMap<String, HashMap<String, bool>>,
    pub unreachable_chains: Vec<(String, String)>,
    pub dangling_jumps: Vec<(RuleId, String)>,
}

/// 规则在其位置上是否终结当前报文路径。
fn is_terminal_at(
    rule: &Rule,
    table_terminal: &HashMap<String, bool>,
) -> bool {
    if rule.verdict.is_terminal_here() {
        return true;
    }
    if rule.verdict.kind == VerdictKind::Jump {
        if let Some(target) = &rule.verdict.target {
            return table_terminal.get(target).copied().unwrap_or(false);
        }
    }
    false
}

fn verdict_key(rule: &Rule) -> String {
    match rule.verdict.kind {
        VerdictKind::Jump | VerdictKind::Goto => format!(
            "{:?}:{}",
            rule.verdict.kind,
            rule.verdict.target.clone().unwrap_or_default()
        ),
        _ => format!("{:?}", rule.verdict.kind),
    }
}

/// 计算每个表内各链是否“必然终结”：
/// 任何报文进入该链后，都会在链内遇到终结规则，不会自然走到链尾/RETURN 回退。
fn compute_always_terminal(ruleset: &Ruleset) -> HashMap<String, HashMap<String, bool>> {
    let mut out: HashMap<String, HashMap<String, bool>> = HashMap::new();
    for table in &ruleset.tables {
        let mut state: HashMap<String, bool> = table
            .chains
            .iter()
            .map(|c| (c.name.clone(), false))
            .collect();

        let mut changed = true;
        while changed {
            changed = false;
            for chain in &table.chains {
                if state[&chain.name] {
                    continue;
                }
                let terminates = chain.rules.iter().any(|r| {
                    // 匹配所有报文（相对全集的子集且非空 —— 非空规则天然是全集子集）
                    !r.matches.is_empty()
                        && r.matches == MatchSet::universe(r.matches.family)
                        && is_terminal_at(r, &state)
                });
                if terminates {
                    state.insert(chain.name.clone(), true);
                    changed = true;
                }
            }
        }
        out.insert(table.name.clone(), state);
    }
    out
}

/// 计算从基础链（有 policy 或 hook）出发可达的链集合。
fn compute_reachable(ruleset: &Ruleset) -> HashSet<(String, String)> {
    let mut reachable: HashSet<(String, String)> = HashSet::new();
    let mut stack: Vec<(String, String)> = Vec::new();

    for table in &ruleset.tables {
        for chain in &table.chains {
            if chain.policy.is_some() || chain.hook.is_some() {
                let key = (table.name.clone(), chain.name.clone());
                if reachable.insert(key.clone()) {
                    stack.push(key);
                }
            }
        }
    }

    while let Some((tname, cname)) = stack.pop() {
        let Some(table) = ruleset.table(&tname) else {
            continue;
        };
        let Some(chain) = table.chain(&cname) else {
            continue;
        };
        for rule in &chain.rules {
            if matches!(rule.verdict.kind, VerdictKind::Jump | VerdictKind::Goto) {
                if let Some(target) = &rule.verdict.target {
                    let key = (tname.clone(), target.clone());
                    if ruleset.table(&tname).and_then(|t| t.chain(target)).is_some()
                        && reachable.insert(key.clone())
                    {
                        stack.push(key);
                    }
                }
            }
        }
    }
    reachable
}

pub fn analyze(ruleset: &Ruleset) -> AnalysisReport {
    let always_terminal = compute_always_terminal(ruleset);
    let reachable = compute_reachable(ruleset);
    let mut report = AnalysisReport {
        always_terminal,
        ..Default::default()
    };

    for table in &ruleset.tables {
        let term_map = report
            .always_terminal
            .get(&table.name)
            .cloned()
            .unwrap_or_default();

        for chain in &table.chains {
            let mut cr = ChainReport {
                table: table.name.clone(),
                chain: chain.name.clone(),
                ..Default::default()
            };
            let chain_key = (table.name.clone(), chain.name.clone());
            if !reachable.contains(&chain_key) {
                cr.unreachable = true;
                report
                    .unreachable_chains
                    .push((table.name.clone(), chain.name.clone()));
            }

            // 链内排在当前规则之前的终结规则（原始匹配空间）。
            let mut prior_terminals: Vec<&Rule> = Vec::new();

            for (idx, rule) in chain.rules.iter().enumerate() {
                // 1) 空匹配 -> 冗余
                if rule.matches.is_empty() {
                    cr.redundant.push(RedundantFinding {
                        rule: rule.id.clone(),
                        reason: RedundantReason::EmptyMatch,
                    });
                }

                // 2) 完全相同匹配空间 -> 冗余
                for prev in chain.rules[..idx].iter() {
                    if prev.matches == rule.matches && !rule.matches.is_empty() {
                        cr.redundant.push(RedundantFinding {
                            rule: rule.id.clone(),
                            reason: RedundantReason::DuplicateOf(prev.id.clone()),
                        });
                        break;
                    }
                }

                // 3) 遮蔽分析
                if !rule.matches.is_empty() {
                    let mut remaining = vec![rule.matches.clone()];
                    // 记录每个真正切走过残差的终结规则（按顺序）。
                    let mut contributors: Vec<&Rule> = Vec::new();

                    for term in &prior_terminals {
                        if remaining.is_empty() {
                            break;
                        }
                        // 精确差集扣减：对每个残差块都尝试减去该终结规则。
                        let before: u128 = residual_size(&remaining);
                        let mut next = Vec::new();
                        for piece in &remaining {
                            let inter = piece.intersect(&term.matches);
                            if inter.is_empty() {
                                next.push(piece.clone());
                            } else {
                                next.extend(piece.subtract(&term.matches));
                            }
                        }
                        let after = residual_size(&next);
                        if after < before {
                            contributors.push(term);
                        }
                        remaining = next;
                    }

                    if remaining.is_empty() {
                        // 单条遮蔽：整个空间 ⊆ 某条终结规则
                        let single_cover = contributors
                            .iter()
                            .find(|t| rule.matches.is_subset_of(&t.matches))
                            .map(|t| t.id.clone());
                        // 最小化联合遮蔽：从后往前剔除“非必要”的贡献者，
                        // 只保留对最终归零不可或缺的规则，避免列出无关规则。
                        let minimal = minimal_cover(&rule.matches, &contributors);
                        let by_combination: Vec<RuleId> =
                            minimal.iter().map(|r| r.id.clone()).collect();
                        cr.shadowed.push(ShadowFinding {
                            rule: rule.id.clone(),
                            by_single: single_cover,
                            by_combination,
                        });
                    }
                }

                // 4) 冲突分析
                for prev in chain.rules[..idx].iter() {
                    if rule.matches.is_empty() || prev.matches.is_empty() {
                        continue;
                    }
                    let inter = prev.matches.intersect(&rule.matches);
                    if inter.is_empty() {
                        continue;
                    }
                    if verdict_key(prev) != verdict_key(rule) {
                        cr.conflicts.push(ConflictFinding {
                            first: prev.id.clone(),
                            second: rule.id.clone(),
                            intersection: inter,
                        });
                    }
                }

                // 5) 悬空跳转
                if matches!(rule.verdict.kind, VerdictKind::Jump | VerdictKind::Goto) {
                    if let Some(target) = &rule.verdict.target {
                        if ruleset
                            .table(&table.name)
                            .and_then(|t| t.chain(target))
                            .is_none()
                        {
                            report
                                .dangling_jumps
                                .push((rule.id.clone(), target.clone()));
                        }
                    }
                }

                if is_terminal_at(rule, &term_map) && !rule.matches.is_empty() {
                    prior_terminals.push(rule);
                }
            }

            report.chains.push(cr);
        }
    }
    report
}

/// 残差规模度量：对各数值字段的区间总宽度做“对数化”求和，
/// 接口字段用原子数近似。只用于比较扣减前后大小，不做精确报文计数（地址域可达 2^128）。
fn residual_size(pieces: &[MatchSet]) -> u128 {
    let mut total: u128 = 0;
    for p in pieces {
        let width = |ranges: &[(u128, u128)]| -> u128 {
            ranges
                .iter()
                .map(|(lo, hi)| hi.saturating_sub(*lo).saturating_add(1))
                .fold(0u128, |acc, w| acc.saturating_add(w))
        };
        // 用字段宽度之和作为该块的体积代理；空块为 0。
        let vol = width(p.src_ip.ranges())
            .saturating_add(width(p.dst_ip.ranges()))
            .saturating_add(width(p.proto.ranges()))
            .saturating_add(width(p.src_port.ranges()))
            .saturating_add(width(p.dst_port.ranges()))
            .saturating_add(width(p.icmp_type.ranges()))
            .saturating_add(width(p.state.ranges()))
            .saturating_add(p.iif.atoms.len() as u128)
            .saturating_add(p.oif.atoms.len() as u128);
        total = total.saturating_add(vol);
    }
    total
}

/// 给定已确认能把 `target` 扣减为空的有序贡献者列表，
/// 返回保持顺序的最小必要子集（反向贪心剔除可去掉者）。
fn minimal_cover<'a>(target: &MatchSet, contributors: &[&'a Rule]) -> Vec<&'a Rule> {
    // 先验证全量确实覆盖；再逐个尝试移除，移除后仍能归零则永久剔除。
    let covers = |subset: &[&Rule]| -> bool {
        let mut remaining = vec![target.clone()];
        for r in subset {
            if remaining.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for piece in &remaining {
                if piece.intersect(&r.matches).is_empty() {
                    next.push(piece.clone());
                } else {
                    next.extend(piece.subtract(&r.matches));
                }
            }
            remaining = next;
        }
        remaining.is_empty()
    };

    if !covers(contributors) {
        // 理论上不会发生；保守返回全量
        return contributors.to_vec();
    }

    let mut kept: Vec<&Rule> = contributors.to_vec();
    let mut idx = 0;
    while idx < kept.len() {
        let mut trial: Vec<&Rule> = kept[..idx].to_vec();
        trial.extend_from_slice(&kept[idx + 1..]);
        if covers(&trial) {
            kept = trial; // 剔除 idx 后仍覆盖，永久移除，不推进 idx
        } else {
            idx += 1;
        }
    }
    kept
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use crate::intervals::IntervalSet;
    use crate::ip::{Family, IpNet};

    fn mk_id(t: &str, c: &str, idx: usize) -> RuleId {
        RuleId { table: t.into(), chain: c.into(), index: idx }
    }

    fn mk_rule(idx: usize, m: MatchSet, kind: VerdictKind, target: Option<&str>) -> Rule {
        Rule {
            id: mk_id("filter", "INPUT", idx),
            file: "t".into(),
            line_no: idx + 1,
            raw: format!("r{idx}"),
            matches: m,
            verdict: Verdict {
                kind,
                target: target.map(String::from),
                detail: None,
                raw: format!("{kind:?}"),
            },
            unsupported: vec![],
        }
    }

    fn src_cidr(fam: Family, cidr: &str) -> MatchSet {
        let mut m = MatchSet::universe(fam);
        let n = IpNet::parse(cidr).unwrap();
        let (lo, hi) = n.range();
        m.src_ip = IntervalSet::range(lo, hi);
        m
    }

    fn build(rules: Vec<Rule>) -> Ruleset {
        Ruleset {
            tables: vec![Table {
                name: "filter".into(),
                family: Family::V4,
                chains: vec![Chain {
                    name: "INPUT".into(),
                    policy: Some("DROP".into()),
                    counters: (0, 0),
                    hook: None,
                    rules,
                }],
            }],
            warnings: vec![],
        }
    }

    #[test]
    fn single_shadow_detected() {
        let wide = src_cidr(Family::V4, "10.0.0.0/8");
        let narrow = src_cidr(Family::V4, "10.1.2.3/32");
        let rs = build(vec![
            mk_rule(0, wide, VerdictKind::Drop, None),
            mk_rule(1, narrow, VerdictKind::Accept, None),
        ]);
        let rep = analyze(&rs);
        let cr = &rep.chains[0];
        assert_eq!(cr.shadowed.len(), 1);
        assert_eq!(cr.shadowed[0].rule.index, 1);
        assert_eq!(cr.shadowed[0].by_single.as_ref().unwrap().index, 0);
    }

    #[test]
    fn adjacent_cidr_not_shadowed() {
        // 10.0.0.0/24 与 10.0.1.0/24 相邻不相交，后者不能被遮蔽
        let a = src_cidr(Family::V4, "10.0.0.0/24");
        let b = src_cidr(Family::V4, "10.0.1.0/24");
        let rs = build(vec![
            mk_rule(0, a, VerdictKind::Drop, None),
            mk_rule(1, b, VerdictKind::Accept, None),
        ]);
        let rep = analyze(&rs);
        assert!(rep.chains[0].shadowed.is_empty());
        assert!(rep.chains[0].conflicts.is_empty());
    }

    #[test]
    fn combined_shadow_tcp_and_not_tcp() {
        let net = "172.16.0.0/16";
        let mut tcp = src_cidr(Family::V4, net);
        tcp.proto = IntervalSet::point(6);
        let mut nottcp = src_cidr(Family::V4, net);
        nottcp.proto = IntervalSet::universe(255).subtract(&IntervalSet::point(6));
        let target = src_cidr(Family::V4, "172.16.5.5/32");
        let rs = build(vec![
            mk_rule(0, tcp, VerdictKind::Drop, None),
            mk_rule(1, nottcp, VerdictKind::Drop, None),
            mk_rule(2, target, VerdictKind::Accept, None),
        ]);
        let rep = analyze(&rs);
        let sh = &rep.chains[0].shadowed;
        assert_eq!(sh.len(), 1, "应只有 #2 被遮蔽");
        assert_eq!(sh[0].rule.index, 2);
        assert!(sh[0].by_single.is_none(), "无单条可遮蔽");
        assert_eq!(sh[0].by_combination.len(), 2);
    }

    #[test]
    fn conflict_but_not_shadow_when_verdict_accept_below() {
        // 窄 ACCEPT 在宽 DROP 之后：既冲突又遮蔽（DROP 在前终结）
        let wide = src_cidr(Family::V4, "10.0.0.0/8");
        let narrow = src_cidr(Family::V4, "10.0.0.5/32");
        let rs = build(vec![
            mk_rule(0, wide, VerdictKind::Drop, None),
            mk_rule(1, narrow, VerdictKind::Accept, None),
        ]);
        let rep = analyze(&rs);
        assert_eq!(rep.chains[0].conflicts.len(), 1);
        assert_eq!(rep.chains[0].shadowed.len(), 1);
    }

    #[test]
    fn intersect_without_subset_is_conflict_only() {
        // /24 与 /23 部分重叠且互不为子集：
        // 10.0.0.0/24 = .0.0-.0.255；10.0.0.128/25 = .0.128-.0.255（前者包含后者，仍是子集）
        // 改用：10.0.0.128/25 (.128-.255) 与 10.0.0.0/25 (.0-.127) 仅在 .128 边界相邻不相交；
        // 真正部分重叠取 10.0.0.0/24 与 10.0.0.64/26（.64-.127 完全在 /24 内，仍是子集）。
        // 两个 CIDR 若同源必然一个包含另一个；要“部分重叠”需用多段集合构造。
        use crate::intervals::IntervalSet;
        let mut wide = MatchSet::universe(Family::V4);
        wide.src_ip = IntervalSet::range(
            crate::ip::IpAddr::parse("10.0.0.0").unwrap().value,
            crate::ip::IpAddr::parse("10.0.0.200").unwrap().value,
        ); // .0-.200
        let mut partial = MatchSet::universe(Family::V4);
        partial.src_ip = IntervalSet::range(
            crate::ip::IpAddr::parse("10.0.0.100").unwrap().value,
            crate::ip::IpAddr::parse("10.0.0.255").unwrap().value,
        ); // .100-.255，与前者重叠 .100-.200，但各有独占区
        let rs = build(vec![
            mk_rule(0, wide, VerdictKind::Drop, None),
            mk_rule(1, partial, VerdictKind::Accept, None),
        ]);
        let rep = analyze(&rs);
        let cr = &rep.chains[0];
        assert_eq!(cr.conflicts.len(), 1, "重叠部分动作不一致 -> 冲突");
        assert!(cr.shadowed.is_empty(), "部分重叠不能完全遮蔽");
    }
}

