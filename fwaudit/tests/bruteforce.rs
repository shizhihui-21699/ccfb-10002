//! Cross-check the analyzer against brute-force packet enumeration.
//!
//! The analyzer works on exact CIDR intervals; here we verify it on randomly
//! generated rulesets over a tiny packet space where we can afford to
//! simulate every single packet by hand. Any disagreement is a bug.

use fwaudit::analysis;
use fwaudit::model::{Rule, Ruleset, Target};
use fwaudit::rect::{Family, IntervalSet, Rect, DIM_DPORT, DIM_PROTO, DIM_SRC, NDIMS};

/// simple deterministic PRNG (xorshift64)
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const SRC_SPACE: u64 = 16; // 10.0.0.0/28
const PORTS: [u64; 3] = [22, 80, 443];
const PROTOS: [u64; 2] = [6, 17];

fn random_ruleset(seed: u64, n_rules: usize) -> Ruleset {
    let mut rng = Rng(seed);
    let mut rs = Ruleset::default();
    rs.get_or_add_chain("filter", "INPUT");
    rs.chains[0].builtin = true;
    rs.chains[0].policy = Some("DROP".into());
    for i in 0..n_rules {
        // random src: a sub-range of the 16-address space
        let lo = rng.below(SRC_SPACE) as u128;
        let hi = (lo + rng.below(SRC_SPACE - lo as u64) as u128).min(SRC_SPACE as u128 - 1);
        let port = PORTS[rng.below(3) as usize];
        let proto = PROTOS[rng.below(2) as usize];
        let action = if rng.below(2) == 0 { "ACCEPT" } else { "DROP" };
        let mut r = Rect::full(Family::V4);
        r.dims[DIM_SRC] = IntervalSet::single(lo, hi);
        r.dims[DIM_PROTO] = IntervalSet::single(proto as u128, proto as u128);
        r.dims[DIM_DPORT] = IntervalSet::single(port as u128, port as u128);
        rs.add_rule(Rule {
            table: "filter".into(),
            chain: "INPUT".into(),
            index: 0,
            text: format!("rule{i}: src={lo}-{hi} proto={proto} dport={port} -> {action}"),
            mset: vec![r],
            target: Target::Terminal(action.into()),
            origin: "generated".into(),
        });
    }
    rs
}

/// For every packet in the tiny space, find the first terminal rule that
/// matches it (true first-match semantics). Returns fired[rule] = bool.
fn brute_force_fired(rs: &Ruleset) -> Vec<bool> {
    let chain = &rs.chains[0];
    let mut fired = vec![false; rs.rules.len()];
    for src in 0..SRC_SPACE as u128 {
        for &proto in &PROTOS {
            for &port in &PORTS {
                let pt: [u128; NDIMS] = [src, 0, proto as u128, 0, port as u128];
                for &ridx in &chain.rules {
                    let rule = &rs.rules[ridx];
                    if !rule.target.is_terminal() {
                        continue;
                    }
                    if rule.mset.iter().any(|r| r.contains_point(&pt)) {
                        fired[ridx] = true;
                        break; // first match wins
                    }
                }
            }
        }
    }
    fired
}

#[test]
fn analyzer_matches_brute_force() {
    for seed in 1..200u64 {
        let rs = random_ruleset(seed, 12);
        let rep = analysis::analyze(&rs);
        let fired = brute_force_fired(&rs);
        // collect analyzer's dead rules
        let mut dead = vec![false; rs.rules.len()];
        for crep in &rep.chains {
            for f in crep.shadowed.iter().chain(crep.redundant.iter()) {
                dead[f.rule] = true;
            }
        }
        for (ridx, rule) in rs.rules.iter().enumerate() {
            assert_eq!(
                dead[ridx], !fired[ridx],
                "seed {seed} rule #{} '{}': analyzer says dead={}, brute force says fired={}",
                rule.index, rule.text, dead[ridx], fired[ridx]
            );
        }
    }
}

/// Redundant vs shadowed classification: a dead rule whose every covering
/// packet would get the same action must be "redundant", else "shadowed".
#[test]
fn redundant_classification_matches_brute_force() {
    for seed in 1000..1100u64 {
        let rs = random_ruleset(seed, 12);
        let rep = analysis::analyze(&rs);
        let chain = &rs.chains[0];
        // brute force: for each dead rule, check whether all packets matching
        // it would receive the same action from earlier rules
        for crep in &rep.chains {
            for (is_red, f) in crep
                .redundant
                .iter()
                .map(|f| (true, f))
                .chain(crep.shadowed.iter().map(|f| (false, f)))
            {
                let rule = &rs.rules[f.rule];
                let Target::Terminal(my_action) = &rule.target else {
                    continue;
                };
                let mut expect_redundant = true;
                'pkts: for src in 0..SRC_SPACE as u128 {
                    for &proto in &PROTOS {
                        for &port in &PORTS {
                            let pt: [u128; NDIMS] = [src, 0, proto as u128, 0, port as u128];
                            if !rule.mset.iter().any(|r| r.contains_point(&pt)) {
                                continue;
                            }
                            // what action does this packet actually get?
                            for &pidx in &chain.rules {
                                let pr = &rs.rules[pidx];
                                if pidx == f.rule {
                                    break; // would reach our rule: uncovered!
                                }
                                if !pr.target.is_terminal() {
                                    continue;
                                }
                                if pr.mset.iter().any(|r| r.contains_point(&pt)) {
                                    if let Target::Terminal(t) = &pr.target {
                                        if t != my_action {
                                            expect_redundant = false;
                                            break 'pkts;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                assert_eq!(
                    is_red, expect_redundant,
                    "seed {seed} rule #{} '{}': classification mismatch",
                    rule.index, rule.text
                );
            }
        }
    }
}
