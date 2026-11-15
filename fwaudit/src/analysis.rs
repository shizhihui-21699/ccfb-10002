//! Shadowing / redundancy / conflict analysis.

use crate::model::{Ruleset, Target};
use crate::rect::*;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct CoverFinding {
    /// global rule index
    pub rule: usize,
    /// covering rules, earliest first (global indices)
    pub covered_by: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct Conflict {
    pub earlier: usize,
    pub later: usize,
    pub region: Vec<Rect>,
}

#[derive(Clone, Debug, Default)]
pub struct ChainReport {
    pub chain: usize,
    pub shadowed: Vec<CoverFinding>,
    pub redundant: Vec<CoverFinding>,
    /// Terminal rule identical in effect to the chain policy for every
    /// packet that reaches it (and all later rules are dead).
    pub policy_redundant: Vec<CoverFinding>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Default)]
pub struct Report {
    pub chains: Vec<ChainReport>,
    pub warnings: Vec<String>,
}

/// A chain is "always-terminal" when every packet entering it reaches a
/// terminal verdict without RETURNing to the caller. Jumps into such chains
/// never come back, so they act as coverers for shadowing analysis.
fn compute_always_terminal(rs: &Ruleset) -> Vec<bool> {
    let mut memo: HashMap<usize, bool> = HashMap::new();
    let mut visiting: HashSet<usize> = HashSet::new();
    for c in 0..rs.chains.len() {
        let v = at_chain(rs, c, &mut memo, &mut visiting);
        memo.insert(c, v);
    }
    (0..rs.chains.len()).map(|i| memo[&i]).collect()
}

fn at_chain(
    rs: &Ruleset,
    cidx: usize,
    memo: &mut HashMap<usize, bool>,
    visiting: &mut HashSet<usize>,
) -> bool {
    if let Some(&v) = memo.get(&cidx) {
        return v;
    }
    if !visiting.insert(cidx) {
        return false; // recursion cycle: conservative
    }
    let chain = &rs.chains[cidx];
    let full = [Rect::full(Family::V4), Rect::full(Family::V6)];
    let mut result = false;
    'outer: for (pos, &ridx) in chain.rules.iter().enumerate() {
        let rule = &rs.rules[ridx];
        // rules before the catching rule must not let packets escape
        for &pidx in &chain.rules[..pos] {
            match &rs.rules[pidx].target {
                Target::Return => continue 'outer,
                Target::Goto(c) => {
                    if let Some(&t) = rs
                        .chain_idx
                        .get(&(rs.rules[pidx].table.clone(), c.clone()))
                    {
                        if !at_chain(rs, t, memo, visiting) {
                            continue 'outer;
                        }
                    } else {
                        continue 'outer;
                    }
                }
                _ => {}
            }
        }
        let terminalish = match &rule.target {
            Target::Terminal(_) => true,
            Target::Jump(c) | Target::Goto(c) => {
                if let Some(&t) = rs.chain_idx.get(&(rule.table.clone(), c.clone())) {
                    at_chain(rs, t, memo, visiting)
                } else {
                    false
                }
            }
            _ => false,
        };
        if !terminalish {
            continue;
        }
        // does this rule catch every packet?
        if let Some(rem) = remainder(&full, &[&rule.mset]) {
            if rem.is_empty() {
                result = true;
                break;
            }
        }
    }
    visiting.remove(&cidx);
    memo.insert(cidx, result);
    result
}

/// Bounding box of a match set, per family, for cheap conflict pre-filtering.
struct BBox {
    family: Family,
    lo: [u128; NDIMS],
    hi: [u128; NDIMS],
}

fn bbox(mset: &[Rect]) -> Vec<BBox> {
    let mut out: Vec<BBox> = Vec::new();
    for r in mset {
        if let Some(b) = out.iter_mut().find(|b| b.family == r.family) {
            for d in 0..NDIMS {
                if let Some(&(lo, _)) = r.dims[d].ivs.first() {
                    b.lo[d] = b.lo[d].min(lo);
                }
                if let Some(&(_, hi)) = r.dims[d].ivs.last() {
                    b.hi[d] = b.hi[d].max(hi);
                }
            }
        } else {
            let mut lo = [u128::MAX; NDIMS];
            let mut hi = [0u128; NDIMS];
            for d in 0..NDIMS {
                lo[d] = r.dims[d].ivs.first().map(|x| x.0).unwrap_or(0);
                hi[d] = r.dims[d].ivs.last().map(|x| x.1).unwrap_or(0);
            }
            out.push(BBox {
                family: r.family,
                lo,
                hi,
            });
        }
    }
    out
}

fn bbox_overlap(a: &[BBox], b: &[BBox]) -> bool {
    for x in a {
        for y in b {
            if x.family != y.family {
                continue;
            }
            if (0..NDIMS).all(|d| x.lo[d] <= y.hi[d] && y.lo[d] <= x.hi[d]) {
                return true;
            }
        }
    }
    false
}

pub fn analyze(rs: &Ruleset) -> Report {
    let mut report = Report::default();
    let always_terminal = compute_always_terminal(rs);

    // target name used for coverage, per rule (jumps to always-terminal
    // chains count as coverers)
    let coverer_name: Vec<Option<String>> = rs
        .rules
        .iter()
        .map(|r| match &r.target {
            Target::Terminal(t) => Some(t.clone()),
            Target::Jump(c) | Target::Goto(c) => {
                if let Some(&t) = rs.chain_idx.get(&(r.table.clone(), c.clone())) {
                    if always_terminal[t] {
                        return Some(format!("jump->{c}"));
                    }
                }
                None
            }
            _ => None,
        })
        .collect();

    let bboxes: Vec<Vec<BBox>> = rs.rules.iter().map(|r| bbox(&r.mset)).collect();

    for (cidx, chain) in rs.chains.iter().enumerate() {
        let mut crep = ChainReport {
            chain: cidx,
            ..Default::default()
        };
        let mut coverers: Vec<usize> = Vec::new(); // rule indices that cover
        let mut live: HashMap<usize, Vec<Rect>> = HashMap::new();
        let mut dead: HashMap<usize, bool> = HashMap::new();
        // packets still falling through before the current rule; maintained
        // incrementally, one exact subtraction per coverer
        let mut reach: Vec<Rect> = vec![Rect::full(Family::V4), Rect::full(Family::V6)];
        let mut reach_ok = true;
        // reach snapshots for policy-duplicate candidates (terminal rules
        // whose action equals the chain policy)
        let mut reach_before: HashMap<usize, Vec<Rect>> = HashMap::new();

        for &ridx in &chain.rules {
            let rule = &rs.rules[ridx];
            if reach_ok {
                if let (Target::Terminal(name), Some(pol)) = (&rule.target, &chain.policy) {
                    if name.eq_ignore_ascii_case(pol) {
                        reach_before.insert(ridx, reach.clone());
                    }
                }
            }
            // remainder of this rule after earlier coverers.
            // Pre-filter: a coverer whose bounding box does not overlap this
            // rule's bbox can never subtract anything (rem ⊆ mset).
            let rb = &bboxes[ridx];
            let mut rem: Vec<Rect> = rule.mset.clone();
            let mut used: Vec<usize> = Vec::new();
            let mut blew_up = false;
            for &tidx in &coverers {
                if rem.is_empty() {
                    break;
                }
                if !bbox_overlap(rb, &bboxes[tidx]) {
                    continue;
                }
                match matchset_subtract(&rem, &rs.rules[tidx].mset) {
                    Some((r2, hit)) => {
                        if hit {
                            used.push(tidx);
                        }
                        rem = r2;
                    }
                    None => {
                        blew_up = true;
                        report.warnings.push(format!(
                            "chain {}: rule #{}: match-set too complex, coverage may be incomplete",
                            chain.name, rule.index
                        ));
                        break;
                    }
                }
            }
            let is_dead = !blew_up && rem.is_empty() && !rule.mset.is_empty();
            dead.insert(ridx, is_dead);

            if is_dead {
                let same_action = match &rule.target {
                    Target::Terminal(name) => !used.is_empty()
                        && used.iter().all(|&u| {
                            matches!(&rs.rules[u].target, Target::Terminal(t) if *t == *name)
                        }),
                    _ => false,
                };
                let f = CoverFinding {
                    rule: ridx,
                    covered_by: used.clone(),
                };
                if same_action {
                    crep.redundant.push(f);
                } else {
                    crep.shadowed.push(f);
                }
            }
            live.insert(ridx, rem);

            // update running coverer set and the fall-through set
            if coverer_name[ridx].is_some() {
                coverers.push(ridx);
                if reach_ok && !reach.is_empty() {
                    match matchset_subtract(&reach, &rule.mset) {
                        Some((r2, _)) => reach = r2,
                        None => {
                            reach_ok = false;
                            report.warnings.push(format!(
                                "chain {}: fall-through set too complex, policy-duplicate analysis skipped",
                                chain.name
                            ));
                        }
                    }
                }
            }
        }

        // policy redundancy: live terminal rule whose target equals the
        // chain policy and which catches everything that reaches it, with
        // only dead rules after it
        if let Some(policy) = &chain.policy {
            for (pos, &ridx) in chain.rules.iter().enumerate() {
                let rule = &rs.rules[ridx];
                if dead[&ridx] {
                    continue;
                }
                let Target::Terminal(name) = &rule.target else {
                    continue;
                };
                if name.to_ascii_uppercase() != policy.to_ascii_uppercase() {
                    continue;
                }
                let Some(reach_here) = reach_before.get(&ridx) else {
                    continue;
                };
                if reach_here.is_empty() {
                    continue;
                }
                let catches_all = match matchset_subtract(reach_here, &rule.mset) {
                    Some((r, _)) => r.is_empty(),
                    None => false,
                };
                if !catches_all {
                    continue;
                }
                let later_all_dead = chain.rules[pos + 1..]
                    .iter()
                    .all(|&x| dead.get(&x).copied().unwrap_or(false));
                if later_all_dead {
                    crep.policy_redundant.push(CoverFinding {
                        rule: ridx,
                        covered_by: Vec::new(),
                    });
                }
            }
        }

        // conflicts: earlier live terminal vs later live terminal,
        // different actions, non-empty overlap of live(earlier) with mset(later)
        let terminals: Vec<usize> = chain
            .rules
            .iter()
            .copied()
            .filter(|&r| matches!(rs.rules[r].target, Target::Terminal(_)))
            .collect();
        for (ai, &i) in terminals.iter().enumerate() {
            if dead[&i] {
                continue;
            }
            let Target::Terminal(ti) = &rs.rules[i].target else {
                continue;
            };
            let live_i = &live[&i];
            if live_i.is_empty() {
                continue;
            }
            for &j in &terminals[ai + 1..] {
                if dead[&j] {
                    continue;
                }
                let Target::Terminal(tj) = &rs.rules[j].target else {
                    continue;
                };
                if ti == tj {
                    continue;
                }
                if !bbox_overlap(&bboxes[i], &bboxes[j]) {
                    continue;
                }
                let mut region = Vec::new();
                for ri in live_i {
                    for rj in &rs.rules[j].mset {
                        if let Some(x) = ri.intersect(rj) {
                            region.push(x);
                            if region.len() > 64 {
                                break;
                            }
                        }
                    }
                    if region.len() > 64 {
                        break;
                    }
                }
                if !region.is_empty() {
                    crep.conflicts.push(Conflict {
                        earlier: i,
                        later: j,
                        region,
                    });
                }
            }
        }

        if !crep.shadowed.is_empty()
            || !crep.redundant.is_empty()
            || !crep.policy_redundant.is_empty()
            || !crep.conflicts.is_empty()
        {
            report.chains.push(crep);
        }
    }
    report
}
