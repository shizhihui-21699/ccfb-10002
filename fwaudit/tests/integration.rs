//! End-to-end tests on the deliberately-broken fixtures.
//! Every planted problem must be found — no misses allowed.

use fwaudit::analysis;
use fwaudit::model::{Ruleset, Target};
use fwaudit::{parse_iptables, parse_nft, simulate};
use std::collections::BTreeSet;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn load_ipt() -> Ruleset {
    parse_iptables::parse(&std::fs::read_to_string(fixture("broken.v4")).unwrap(), "broken.v4")
}

fn load_nft() -> Ruleset {
    parse_nft::parse(&std::fs::read_to_string(fixture("broken.nft")).unwrap(), "broken.nft")
}

/// (kind, rule index in chain) pairs for one chain
fn findings(rs: &Ruleset, rep: &analysis::Report, chain: &str) -> BTreeSet<(String, usize)> {
    let mut out = BTreeSet::new();
    for crep in &rep.chains {
        let c = &rs.chains[crep.chain];
        if c.name != chain {
            continue;
        }
        for f in &crep.shadowed {
            out.insert(("shadowed".to_string(), rs.rules[f.rule].index));
        }
        for f in &crep.redundant {
            out.insert(("redundant".to_string(), rs.rules[f.rule].index));
        }
        for f in &crep.policy_redundant {
            out.insert(("policydup".to_string(), rs.rules[f.rule].index));
        }
    }
    out
}

fn conflicts(
    rs: &Ruleset,
    rep: &analysis::Report,
    chain: &str,
) -> BTreeSet<(usize, usize)> {
    let mut out = BTreeSet::new();
    for crep in &rep.chains {
        let c = &rs.chains[crep.chain];
        if c.name != chain {
            continue;
        }
        for cf in &crep.conflicts {
            out.insert((rs.rules[cf.earlier].index, rs.rules[cf.later].index));
        }
    }
    out
}

#[test]
fn iptables_shadow_redundant_policy() {
    let rs = load_ipt();
    assert!(rs.warnings.is_empty(), "parse warnings: {:?}", rs.warnings);
    let rep = analysis::analyze(&rs);
    let f = findings(&rs, &rep, "INPUT");
    let expect: BTreeSet<(String, usize)> = [
        ("shadowed", 4),
        ("shadowed", 5),
        ("shadowed", 9),
        ("shadowed", 11),
        ("shadowed", 16),
        ("redundant", 2),
        ("redundant", 14),
        ("policydup", 15),
    ]
    .iter()
    .map(|(k, i)| (k.to_string(), *i))
    .collect();
    assert_eq!(f, expect, "iptables findings mismatch");
}

#[test]
fn iptables_conflicts() {
    let rs = load_ipt();
    let rep = analysis::analyze(&rs);
    let c = conflicts(&rs, &rep, "INPUT");
    // planted: (1,3) 10/8 drop vs ssh accept, (6,7) /16 drop vs /15 accept
    assert!(c.contains(&(1, 3)), "missing conflict 1/3: {c:?}");
    assert!(c.contains(&(6, 7)), "missing conflict 6/7: {c:?}");
    // rule 2 is dead (subset of 1, same action): must not appear in conflicts
    assert!(c.iter().all(|&(_, j)| j != 2));
}

#[test]
fn iptables_coverer_identity() {
    let rs = load_ipt();
    let rep = analysis::analyze(&rs);
    for crep in &rep.chains {
        if rs.chains[crep.chain].name != "INPUT" {
            continue;
        }
        // rule 11 (172.16.8/24 accept) must be shadowed via the LOGDROP jump
        for f in &crep.shadowed {
            if rs.rules[f.rule].index == 11 {
                let texts: Vec<&str> = f
                    .covered_by
                    .iter()
                    .map(|&c| rs.rules[c].text.as_str())
                    .collect();
                assert!(
                    texts.iter().any(|t| t.contains("LOGDROP")),
                    "rule 11 coverers missing LOGDROP jump: {texts:?}"
                );
                return;
            }
        }
        panic!("rule 11 not reported shadowed");
    }
    panic!("no INPUT chain report");
}

#[test]
fn nft_shadow_redundant_policy() {
    let rs = load_nft();
    assert!(rs.warnings.is_empty(), "parse warnings: {:?}", rs.warnings);
    let rep = analysis::analyze(&rs);
    let f = findings(&rs, &rep, "input");
    let expect: BTreeSet<(String, usize)> = [
        ("shadowed", 4),
        ("shadowed", 10),
        ("shadowed", 13),
        ("shadowed", 15),
        ("redundant", 2),
        ("redundant", 8),
        ("policydup", 14),
    ]
    .iter()
    .map(|(k, i)| (k.to_string(), *i))
    .collect();
    assert_eq!(f, expect, "nft findings mismatch");
}

#[test]
fn nft_conflicts() {
    let rs = load_nft();
    let rep = analysis::analyze(&rs);
    let c = conflicts(&rs, &rep, "input");
    // planted: (5,6) admin /24 accept vs /23 drop
    assert!(c.contains(&(5, 6)), "missing conflict 5/6: {c:?}");
}

#[test]
fn nft_ct_state_not_shadowed() {
    // rule 11 (ct state established,related accept) must stay live
    let rs = load_nft();
    let rep = analysis::analyze(&rs);
    let f = findings(&rs, &rep, "input");
    assert!(!f.contains(&("shadowed".to_string(), 11)));
    assert!(!f.contains(&("redundant".to_string(), 11)));
}

fn pkt(
    src: &str,
    dst: &str,
    proto: &str,
    dport: u16,
) -> simulate::Packet {
    let (fam, s) = fwaudit::parseutil::parse_ip(src).unwrap();
    let (_, d) = fwaudit::parseutil::parse_ip(dst).unwrap();
    simulate::Packet {
        family: fam,
        src: s,
        dst: d,
        proto: fwaudit::parseutil::proto_number(proto).unwrap(),
        sport: 40000,
        dport,
        iif: None,
        oif: None,
    }
}

#[test]
fn simulate_direct_drop() {
    let rs = load_ipt();
    let t = simulate::simulate(&rs, "filter", "INPUT", &pkt("10.1.2.3", "8.8.8.8", "tcp", 22));
    assert_eq!(t.verdict.as_deref(), Some("DROP"));
}

#[test]
fn simulate_jump_no_return() {
    let rs = load_ipt();
    let t = simulate::simulate(&rs, "filter", "INPUT", &pkt("172.16.8.9", "8.8.8.8", "tcp", 12345));
    assert_eq!(t.verdict.as_deref(), Some("DROP"));
    // must have entered LOGDROP
    assert!(t.events.iter().any(|e| matches!(
        e,
        simulate::Event::EnterChain { chain, .. } if chain == "LOGDROP"
    )));
}

#[test]
fn simulate_jump_and_return() {
    let rs = load_ipt();
    // 203.0.113.5:443 hits TRUSTED's accept
    let t = simulate::simulate(&rs, "filter", "INPUT", &pkt("203.0.113.5", "8.8.8.8", "tcp", 443));
    assert_eq!(t.verdict.as_deref(), Some("ACCEPT"));
    // 203.0.113.5:25 returns from TRUSTED, then caught by #15
    let t = simulate::simulate(&rs, "filter", "INPUT", &pkt("203.0.113.5", "8.8.8.8", "tcp", 25));
    assert_eq!(t.verdict.as_deref(), Some("DROP"));
    assert!(t.events.iter().any(|e| matches!(
        e,
        simulate::Event::Return { from, .. } if from == "TRUSTED"
    )));
}

#[test]
fn simulate_policy_fallback() {
    let rs = load_ipt();
    // nothing matches before the catch-all; disable catch-all by using FORWARD
    let t = simulate::simulate(&rs, "filter", "FORWARD", &pkt("1.2.3.4", "8.8.8.8", "udp", 53));
    assert_eq!(t.verdict.as_deref(), Some("DROP"));
}

#[test]
fn simulate_nft_v6() {
    let rs = load_nft();
    let t = simulate::simulate(
        &rs,
        "inet/filter",
        "input",
        &pkt("2001:db8:1::5", "2001:db8::1", "tcp", 22),
    );
    assert_eq!(t.verdict.as_deref(), Some("ACCEPT"));
}

#[test]
fn simulate_nft_named_set() {
    let rs = load_nft();
    let t = simulate::simulate(&rs, "inet/filter", "input", &pkt("172.16.5.5", "8.8.8.8", "tcp", 22));
    assert_eq!(t.verdict.as_deref(), Some("DROP"));
}

#[test]
fn no_chain_is_missing_rules() {
    // rule numbering must be dense and 1-based per chain
    for rs in [load_ipt(), load_nft()] {
        for c in &rs.chains {
            for (pos, &ridx) in c.rules.iter().enumerate() {
                assert_eq!(rs.rules[ridx].index, pos + 1);
            }
        }
    }
}

#[test]
fn targets_resolved() {
    let rs = load_ipt();
    let input = rs.chain("filter", "INPUT").unwrap();
    let r10 = &rs.rules[input.rules[9]];
    assert!(matches!(&r10.target, Target::Jump(c) if c == "LOGDROP"));
    let trusted = rs.chain("filter", "TRUSTED").unwrap();
    let last = &rs.rules[*trusted.rules.last().unwrap()];
    assert!(matches!(&last.target, Target::Return));
}
