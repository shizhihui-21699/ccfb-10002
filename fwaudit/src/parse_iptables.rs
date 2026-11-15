//! Parser for `iptables-save` / `ip6tables-save` output.

use crate::model::{Backend, Rule, Ruleset, Target};
use crate::parseutil::*;
use crate::rect::IntervalSet;

/// Well-known terminating extension targets.
fn is_terminal_target(name: &str) -> bool {
    matches!(
        name,
        "ACCEPT"
            | "DROP"
            | "REJECT"
            | "DNAT"
            | "SNAT"
            | "MASQUERADE"
            | "REDIRECT"
            | "NETMAP"
            | "QUEUE"
            | "NFQUEUE"
            | "NOTRACK"
            | "STOLEN"
            | "TFPROXY"
    )
}

fn is_nonterminal_target(name: &str) -> bool {
    matches!(
        name,
        "LOG"
            | "ULOG"
            | "NFLOG"
            | "MARK"
            | "CONNMARK"
            | "TTL"
            | "CHECKSUM"
            | "SET"
            | "TEE"
            | "SECMARK"
            | "CONNSECMARK"
            | "CT"
            | "DSCP"
            | "TOS"
            | "ECN"
            | "HL"
            | "TRACE"
            | "BPF"
            | "IDLETIMER"
            | "LED"
            | "RATEEST"
            | "TCPMSS"
            | "TCPOPTSTRIP"
            | "SYNPROXY"
            | "HMARK"
            | "RETURN"
    )
}

fn tokenize(line: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut has = false;
    for c in line.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                has = true;
            }
            c if c.is_whitespace() && !in_q => {
                if has {
                    toks.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            _ => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        toks.push(cur);
    }
    toks
}

/// Parse one iptables-save file into a Ruleset.
pub fn parse(text: &str, origin: &str) -> Ruleset {
    let mut rs = Ruleset::new(Backend::Iptables);
    let mut table = String::from("filter");
    // pending rules resolved after we know all chain names in the table
    struct Pending {
        chain: String,
        table: String,
        builder: RuleBuilder,
        text: String,
        line: usize,
    }
    let mut pending: Vec<Pending> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(t) = line.strip_prefix('*') {
            table = t.trim().to_string();
            continue;
        }
        if line == "COMMIT" {
            continue;
        }
        if let Some(rest) = line.strip_prefix(':') {
            // :CHAIN POLICY [counters]
            let mut it = rest.split_whitespace();
            let name = it.next().unwrap_or("");
            let policy = it.next().unwrap_or("-");
            let cidx = rs.get_or_add_chain(&table, name);
            let ch = &mut rs.chains[cidx];
            ch.builtin = policy != "-";
            if ch.builtin {
                ch.policy = Some(policy.to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("-A ") {
            let toks = tokenize(rest);
            if toks.is_empty() {
                continue;
            }
            let chain = toks[0].clone();
            match parse_rule_args(&toks[1..], &mut rs, lineno + 1, origin) {
                Some(builder) => {
                    pending.push(Pending {
                        chain,
                        table: table.clone(),
                        builder,
                        text: line.to_string(),
                        line: lineno + 1,
                    });
                }
                None => {
                    rs.warn(format!(
                        "{origin}:{}: could not parse rule, kept as opaque: {line}",
                        lineno + 1
                    ));
                    let mut b = RuleBuilder::new();
                    b.atoms.push(format!("unparsed: {line}"));
                    b.target = Some(("LOG".into(), false)); // non-terminal placeholder
                    pending.push(Pending {
                        chain,
                        table: table.clone(),
                        builder: b,
                        text: line.to_string(),
                        line: lineno + 1,
                    });
                }
            }
            continue;
        }
        rs.warn(format!("{origin}:{}: ignoring line: {line}", lineno + 1));
    }

    // resolve targets now that all chains are known
    let chain_names: std::collections::BTreeSet<(String, String)> =
        rs.chain_idx.keys().cloned().collect();
    for p in pending {
        let (raw_target, is_goto) = p.builder.target.clone().unwrap_or(("LOG".into(), false));
        let target = resolve_target(&raw_target, is_goto, &p.table, &chain_names, &mut rs, p.line, origin);
        let mset = p.builder.build();
        rs.add_rule(Rule {
            table: p.table,
            chain: p.chain,
            index: 0,
            text: p.text,
            mset,
            target,
            origin: origin.to_string(),
        });
    }
    rs
}

fn resolve_target(
    raw: &str,
    is_goto: bool,
    table: &str,
    chains: &std::collections::BTreeSet<(String, String)>,
    rs: &mut Ruleset,
    line: usize,
    origin: &str,
) -> Target {
    let up = raw.to_ascii_uppercase();
    if up == "RETURN" {
        return Target::Return;
    }
    if is_terminal_target(&up) {
        return Target::Terminal(up);
    }
    if chains.contains(&(table.to_string(), raw.to_string())) {
        return if is_goto {
            Target::Goto(raw.to_string())
        } else {
            Target::Jump(raw.to_string())
        };
    }
    if is_nonterminal_target(&up) {
        return Target::NonTerminal(up);
    }
    rs.warn(format!(
        "{origin}:{line}: unknown target '{raw}', treated as non-terminal"
    ));
    Target::NonTerminal(up)
}

/// Parse the argument list after "-A CHAIN". Returns None on hard failure.
fn parse_rule_args(
    toks: &[String],
    rs: &mut Ruleset,
    lineno: usize,
    origin: &str,
) -> Option<RuleBuilder> {
    let mut b = RuleBuilder::new();
    let mut i = 0;
    let mut negate = false;
    let mut saw_target = false;
    let warn = |rs: &mut Ruleset, msg: String| {
        rs.warn(format!("{origin}:{lineno}: {msg}"));
    };
    while i < toks.len() {
        let t = toks[i].as_str();
        if saw_target {
            // everything after -j/-g is target options, not matches
            i += 1;
            continue;
        }
        if t == "!" {
            negate = true;
            i += 1;
            continue;
        }
        let val = |i: usize| -> Option<&String> { toks.get(i + 1) };
        match t {
            "-s" | "--source" | "--src" => {
                let v = val(i)?;
                let (fam, lo, hi) = parse_addr_spec(v)?;
                b.set_family(fam);
                b.src = Some((
                    fam,
                    if negate {
                        complement(fam, lo, hi)
                    } else {
                        IntervalSet::single(lo, hi)
                    },
                ));
                i += 2;
            }
            "-d" | "--destination" | "--dst" => {
                let v = val(i)?;
                let (fam, lo, hi) = parse_addr_spec(v)?;
                b.set_family(fam);
                b.dst = Some((
                    fam,
                    if negate {
                        complement(fam, lo, hi)
                    } else {
                        IntervalSet::single(lo, hi)
                    },
                ));
                i += 2;
            }
            "-p" | "--protocol" => {
                let v = val(i)?;
                let n = proto_number(v);
                match n {
                    Some(0) => { /* -p all: no constraint */ }
                    Some(n) => {
                        let set = IntervalSet::single(n as u128, n as u128);
                        b.proto = Some(if negate {
                            IntervalSet::full(255).subtract(&set)
                        } else {
                            set
                        });
                    }
                    None => {
                        warn(rs, format!("unknown protocol '{v}', kept as opaque predicate"));
                        b.atoms.push(format!("proto {v}"));
                    }
                }
                i += 2;
            }
            "--sport" | "--sports" | "--source-port" => {
                let v = val(i)?;
                b.sport = Some(parse_port_list(v, negate)?);
                i += 2;
            }
            "--dport" | "--dports" | "--destination-port" => {
                let v = val(i)?;
                b.dport = Some(parse_port_list(v, negate)?);
                i += 2;
            }
            "--ports" => {
                // multiport --ports a,b applies to both
                let v = val(i)?;
                let set = parse_port_list(v, negate)?;
                b.sport = Some(set.clone());
                b.dport = Some(set);
                i += 2;
            }
            "-i" | "--in-interface" => {
                let v = val(i)?.clone();
                if negate || v.contains('+') || v.contains('*') {
                    b.atoms.push(format!("iif {v}"));
                } else {
                    b.iif = Some(v);
                }
                i += 2;
            }
            "-o" | "--out-interface" => {
                let v = val(i)?.clone();
                if negate || v.contains('+') || v.contains('*') {
                    b.atoms.push(format!("oif {v}"));
                } else {
                    b.oif = Some(v);
                }
                i += 2;
            }
            "-j" | "--jump" => {
                let v = val(i)?.clone();
                b.target = Some((v, false));
                saw_target = true;
                i += 2;
            }
            "-g" | "--goto" => {
                let v = val(i)?.clone();
                b.target = Some((v, true));
                saw_target = true;
                i += 2;
            }
            "-m" | "--match" => {
                // module name; known module options are handled by their own
                // flags, unknown ones fall into the generic branch below
                i += 2;
            }
            "--ctstate" | "--state" => {
                let v = val(i)?;
                b.atoms.push(format!("ctstate {v}"));
                i += 2;
            }
            "--comment" => {
                i += 2; // metadata, not a match
            }
            "--tcp-flags" => {
                let a = val(i)?;
                let c = toks.get(i + 2)?;
                b.atoms.push(format!("tcp-flags {a} {c}"));
                i += 3;
            }
            "--icmp-type" | "--icmpv6-type" => {
                let v = val(i)?;
                b.atoms.push(format!("{t} {v}"));
                i += 2;
            }
            "-c" | "--set-counters" => {
                i += 3; // packets bytes
            }
            "-4" | "-6" | "-n" | "-v" | "-x" | "--line-numbers" => {
                i += 1;
            }
            "-t" | "--table" => {
                i += 2; // table already given by *table line; tolerate
            }
            other => {
                // unknown match option: keep as opaque predicate (sound)
                let next_is_val = toks
                    .get(i + 1)
                    .map(|n| !n.starts_with('-'))
                    .unwrap_or(false);
                if next_is_val {
                    b.atoms.push(format!("{other} {}", toks[i + 1]));
                    i += 2;
                } else {
                    b.atoms.push(other.to_string());
                    i += 1;
                }
            }
        }
        negate = false;
    }
    Some(b)
}

/// "80", "80,443", "1000:2000,8080" -> IntervalSet (complement if negated)
fn parse_port_list(s: &str, negate: bool) -> Option<IntervalSet> {
    let mut ivs = Vec::new();
    for part in s.split(',') {
        let (lo, hi) = parse_port_range(part.trim())?;
        ivs.push((lo as u128, hi as u128));
    }
    let set = IntervalSet::from_unsorted(ivs);
    Some(if negate {
        IntervalSet::full(65535).subtract(&set)
    } else {
        set
    })
}
