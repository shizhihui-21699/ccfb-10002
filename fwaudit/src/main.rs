use fwaudit::analysis::{self, ChainReport, Report};
use fwaudit::json::{self, J};
use fwaudit::model::{Backend, Ruleset};
use fwaudit::rect::{self, fmt_rect, Family};
use fwaudit::{parse_iptables, parse_nft, parseutil, simulate};
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

const USAGE: &str = "\
fwaudit — firewall ruleset auditor (iptables-save / nftables)

USAGE:
  fwaudit analyze  --input FILE [--input FILE...] [options]
  fwaudit simulate --input FILE --src IP --dst IP --proto P [options]

COMMON OPTIONS:
  --input FILE        ruleset export ('-' for stdin); repeatable
  --format FMT        auto | iptables | nftables (default: auto, per file)
  --json [FILE]       also write JSON report (stdout if FILE omitted)
  --backend B         iptables | nftables (needed only if both kinds loaded)

ANALYZE finds, per chain:
  SHADOWED   rules fully covered by earlier rules (lists the covering rules)
  REDUNDANT  rules fully covered by earlier rules with the same action
  POLICY-REDUNDANT  terminal rules that just repeat the chain policy
  CONFLICT   rule pairs with different actions whose live match sets overlap

SIMULATE OPTIONS:
  --src IP --dst IP --proto tcp|udp|NUM
  --sport N --dport N        (default 0)
  --table T                  (default: filter)
  --chain C                  start chain (default: INPUT)
  --iif NAME --oif NAME      (rules with interface matches need these)
";

struct Args {
    cmd: String,
    inputs: Vec<String>,
    format: String,
    json: Option<Option<String>>,
    backend: Option<String>,
    src: Option<String>,
    dst: Option<String>,
    proto: Option<String>,
    sport: u16,
    dport: u16,
    table: String,
    chain: String,
    iif: Option<String>,
    oif: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        cmd: String::new(),
        inputs: Vec::new(),
        format: "auto".into(),
        json: None,
        backend: None,
        src: None,
        dst: None,
        proto: None,
        sport: 0,
        dport: 0,
        table: "filter".into(),
        chain: "INPUT".into(),
        iif: None,
        oif: None,
    };
    let mut it = std::env::args().skip(1);
    a.cmd = it.next().unwrap_or_default();
    if a.cmd.is_empty() || a.cmd == "-h" || a.cmd == "--help" || a.cmd == "help" {
        return Err(USAGE.into());
    }
    if a.cmd != "analyze" && a.cmd != "simulate" {
        return Err(format!("unknown command '{}'\n\n{USAGE}", a.cmd));
    }
    while let Some(arg) = it.next() {
        let mut take = |what: &str| -> Result<String, String> {
            it.next().ok_or_else(|| format!("missing value for {what}"))
        };
        match arg.as_str() {
            "--input" | "-i" => a.inputs.push(take("--input")?),
            "--format" | "-f" => a.format = take("--format")?,
            "--json" => {
                // optional value: --json FILE or bare --json
                a.json = Some(match it.next() {
                    Some(v) if !v.starts_with('-') => Some(v),
                    Some(v) => {
                        // put it back conceptually: flags can't follow a bare
                        // --json in our grammar, so treat as missing value
                        return Err(format!("unexpected '{v}' after --json"));
                    }
                    None => None,
                });
            }
            "--backend" => a.backend = Some(take("--backend")?),
            "--src" => a.src = Some(take("--src")?),
            "--dst" => a.dst = Some(take("--dst")?),
            "--proto" => a.proto = Some(take("--proto")?),
            "--sport" => a.sport = take("--sport")?.parse().map_err(|_| "bad --sport")?,
            "--dport" => a.dport = take("--dport")?.parse().map_err(|_| "bad --dport")?,
            "--table" => a.table = take("--table")?,
            "--chain" => a.chain = take("--chain")?,
            "--iif" => a.iif = Some(take("--iif")?),
            "--oif" => a.oif = Some(take("--oif")?),
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }
    if a.inputs.is_empty() {
        return Err("at least one --input is required\n\n".to_string() + USAGE);
    }
    Ok(a)
}

fn detect_format(text: &str) -> Option<Backend> {
    let mut ipt = false;
    for line in text.lines() {
        let l = line.trim_start();
        if l.starts_with("table ") && l.contains('{') || l.starts_with("table ") && !l.contains(' ') {
            return Some(Backend::Nftables);
        }
        if l.starts_with("table ") {
            return Some(Backend::Nftables);
        }
        if l.starts_with('*') || l.starts_with("-A ") || l.starts_with(": ") || l.starts_with(':') {
            ipt = true;
        }
    }
    if ipt {
        Some(Backend::Iptables)
    } else {
        None
    }
}

fn load_rulesets(a: &Args) -> Result<(Ruleset, Ruleset), String> {
    let mut ipt = Ruleset::new(Backend::Iptables);
    let mut nft = Ruleset::new(Backend::Nftables);
    for path in &a.inputs {
        let text = if path == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| format!("reading stdin: {e}"))?;
            s
        } else {
            std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?
        };
        let fmt = match a.format.as_str() {
            "iptables" => Backend::Iptables,
            "nftables" => Backend::Nftables,
            "auto" => detect_format(&text)
                .ok_or_else(|| format!("{path}: cannot detect format (use --format)"))?,
            other => return Err(format!("unknown --format '{other}'")),
        };
        match fmt {
            Backend::Iptables => ipt.merge(parse_iptables::parse(&text, path)),
            Backend::Nftables => nft.merge(parse_nft::parse(&text, path)),
        }
    }
    Ok((ipt, nft))
}

// ---------- terminal rendering ----------

struct Paint {
    on: bool,
}
impl Paint {
    fn c(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn red(&self, s: &str) -> String {
        self.c("31", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.c("33", s)
    }
    fn magenta(&self, s: &str) -> String {
        self.c("35", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.c("36", s)
    }
    fn bold(&self, s: &str) -> String {
        self.c("1", s)
    }
}

fn rule_label(rs: &Ruleset, ridx: usize) -> String {
    let r = &rs.rules[ridx];
    format!("#{} {}", r.index, r.text)
}

fn print_chain_report(rs: &Ruleset, crep: &ChainReport, p: &Paint, out: &mut String) {
    let chain = &rs.chains[crep.chain];
    let policy = chain
        .policy
        .as_deref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".into());
    out.push_str(&format!(
        "\n{} {}\n",
        p.bold(&format!("Chain {}", chain.name)),
        p.cyan(&format!("(table {}, policy {}, {} rules)", chain.table, policy, chain.rules.len()))
    ));
    for f in &crep.shadowed {
        out.push_str(&format!(
            "  {} {}\n",
            p.red("SHADOWED "),
            rule_label(rs, f.rule)
        ));
        let coverers = f
            .covered_by
            .iter()
            .map(|&c| format!("#{} ({})", rs.rules[c].index, rs.rules[c].target.describe()))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("             covered by: {coverers}\n"));
    }
    for f in &crep.redundant {
        out.push_str(&format!(
            "  {} {}\n",
            p.yellow("REDUNDANT"),
            rule_label(rs, f.rule)
        ));
        let coverers = f
            .covered_by
            .iter()
            .map(|&c| format!("#{}", rs.rules[c].index))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "             same action already applied by: {coverers}\n"
        ));
    }
    for f in &crep.policy_redundant {
        out.push_str(&format!(
            "  {} {}\n",
            p.yellow("POLICY-DUP"),
            rule_label(rs, f.rule)
        ));
        out.push_str("             catches everything that reaches it; chain policy does the same\n");
    }
    for c in &crep.conflicts {
        let (ei, li) = (&rs.rules[c.earlier], &rs.rules[c.later]);
        out.push_str(&format!(
            "  {} #{} ({}) vs #{} ({})\n",
            p.magenta("CONFLICT "),
            ei.index,
            ei.target.describe(),
            li.index,
            li.target.describe()
        ));
        out.push_str(&format!("             earlier: {}\n", ei.text));
        out.push_str(&format!("             later:   {}\n", li.text));
        let max_show = 3;
        for r in c.region.iter().take(max_show) {
            out.push_str(&format!("             overlap: {}\n", fmt_rect(r)));
        }
        if c.region.len() > max_show {
            out.push_str(&format!(
                "             ... and {} more overlap pieces\n",
                c.region.len() - max_show
            ));
        }
    }
}

fn report_json(rs: &Ruleset, rep: &Report) -> J {
    let mut root = J::obj();
    root.put("backend", J::str(rs.backend.name()));
    let mut chains = Vec::new();
    for crep in &rep.chains {
        let chain = &rs.chains[crep.chain];
        let mut c = J::obj();
        c.put("table", J::str(&chain.table));
        c.put("chain", J::str(&chain.name));
        c.put(
            "policy",
            chain.policy.as_deref().map(J::str).unwrap_or(J::Null),
        );
        let cov = |f: &analysis::CoverFinding| {
            let mut o = J::obj();
            o.put("rule", J::Num(rs.rules[f.rule].index as u64));
            o.put("text", J::str(&rs.rules[f.rule].text));
            o.put(
                "covered_by",
                J::arr(f.covered_by.iter().map(|&x| {
                    let mut o = J::obj();
                    o.put("rule", J::Num(rs.rules[x].index as u64));
                    o.put("text", J::str(&rs.rules[x].text));
                    o
                })),
            );
            o
        };
        c.put("shadowed", J::arr(crep.shadowed.iter().map(cov)));
        c.put("redundant", J::arr(crep.redundant.iter().map(cov)));
        c.put("policy_redundant", J::arr(crep.policy_redundant.iter().map(cov)));
        c.put(
            "conflicts",
            J::arr(crep.conflicts.iter().map(|cf| {
                let mut o = J::obj();
                let mut e = J::obj();
                e.put("rule", J::Num(rs.rules[cf.earlier].index as u64));
                e.put("text", J::str(&rs.rules[cf.earlier].text));
                e.put("action", J::str(rs.rules[cf.earlier].target.describe()));
                let mut l = J::obj();
                l.put("rule", J::Num(rs.rules[cf.later].index as u64));
                l.put("text", J::str(&rs.rules[cf.later].text));
                l.put("action", J::str(rs.rules[cf.later].target.describe()));
                o.put("earlier", e);
                o.put("later", l);
                o.put(
                    "overlap",
                    J::arr(cf.region.iter().map(|r| J::str(fmt_rect(r)))),
                );
                o
            })),
        );
        chains.push(c);
    }
    root.put("chains", J::Arr(chains));
    root.put(
        "warnings",
        J::arr(rep.warnings.iter().map(|w| J::str(w))),
    );
    root.put(
        "parse_warnings",
        J::arr(rs.warnings.iter().map(|w| J::str(w))),
    );
    root
}

fn cmd_analyze(a: &Args) -> Result<(), String> {
    let (ipt, nft) = load_rulesets(a)?;
    let p = Paint {
        on: std::io::stdout().is_terminal(),
    };
    let mut out = String::new();
    let mut json_roots = Vec::new();
    let mut totals = (0usize, 0usize, 0usize, 0usize);

    for rs in [&ipt, &nft] {
        if rs.rules.is_empty() {
            continue;
        }
        let rep = analysis::analyze(rs);
        out.push_str(&format!(
            "\n{}",
            p.bold(&format!(
                "=== {} · {} chains, {} rules ===",
                rs.backend.name(),
                rs.chains.len(),
                rs.rules.len()
            ))
        ));
        for crep in &rep.chains {
            print_chain_report(rs, crep, &p, &mut out);
            totals.0 += crep.shadowed.len();
            totals.1 += crep.redundant.len();
            totals.2 += crep.policy_redundant.len();
            totals.3 += crep.conflicts.len();
        }
        for w in &rep.warnings {
            out.push_str(&format!("\n{}\n", p.yellow(&format!("warning: {w}"))));
        }
        for w in &rs.warnings {
            out.push_str(&format!("{}\n", p.yellow(&format!("warning: {w}"))));
        }
        if let Some(j) = &a.json {
            let _ = j;
            json_roots.push(report_json(rs, &rep));
        }
        if rep.chains.is_empty() {
            out.push_str(&format!("\n  {}\n", p.cyan("no shadowed, redundant or conflicting rules found")));
        }
    }

    out.push_str(&format!(
        "\n{}\n",
        p.bold(&format!(
            "Summary: {} shadowed, {} redundant, {} policy-duplicate, {} conflicts",
            totals.0, totals.1, totals.2, totals.3
        ))
    ));
    print!("{out}");

    if let Some(dest) = &a.json {
        let payload = if json_roots.len() == 1 {
            json::render(&json_roots[0])
        } else {
            json::render(&J::Arr(json_roots))
        };
        match dest {
            Some(path) => std::fs::write(path, payload)
                .map_err(|e| format!("writing {path}: {e}"))?,
            None => println!("{payload}"),
        }
    }
    Ok(())
}

fn cmd_simulate(a: &Args) -> Result<(), String> {
    let (ipt, nft) = load_rulesets(a)?;
    let rs: &Ruleset = match a.backend.as_deref() {
        Some("iptables") => &ipt,
        Some("nftables") => &nft,
        Some(other) => return Err(format!("unknown backend '{other}'")),
        None => {
            if !ipt.rules.is_empty() && nft.rules.is_empty() {
                &ipt
            } else if ipt.rules.is_empty() && !nft.rules.is_empty() {
                &nft
            } else {
                return Err("both backends loaded; pick one with --backend".into());
            }
        }
    };
    if rs.rules.is_empty() {
        return Err("no rules loaded for the selected backend".into());
    }
    let src_s = a.src.as_deref().ok_or("--src is required")?;
    let dst_s = a.dst.as_deref().ok_or("--dst is required")?;
    let (sfam, src) = parseutil::parse_ip(src_s).ok_or("bad --src address")?;
    let (dfam, dst) = parseutil::parse_ip(dst_s).ok_or("bad --dst address")?;
    if sfam != dfam {
        return Err("--src and --dst must be the same address family".into());
    }
    let proto_s = a.proto.as_deref().ok_or("--proto is required")?;
    let proto = parseutil::proto_number(proto_s).ok_or("bad --proto")?;
    let pkt = simulate::Packet {
        family: if sfam == Family::V4 { Family::V4 } else { Family::V6 },
        src,
        dst,
        proto,
        sport: a.sport,
        dport: a.dport,
        iif: a.iif.clone(),
        oif: a.oif.clone(),
    };
    let trace = simulate::simulate(rs, &a.table, &a.chain, &pkt);

    let p = Paint {
        on: std::io::stdout().is_terminal(),
    };
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        p.bold(&format!(
            "Packet: {} {}:{} -> {}:{}{}",
            rect::proto_display(proto),
            src_s,
            a.sport,
            dst_s,
            a.dport,
            match (&a.iif, &a.oif) {
                (None, None) => String::new(),
                (i, o) => format!(
                    " iif={} oif={}",
                    i.as_deref().unwrap_or("any"),
                    o.as_deref().unwrap_or("any")
                ),
            }
        ))
    ));
    for ev in &trace.events {
        use simulate::Event::*;
        match ev {
            EnterChain { chain, via } => {
                out.push_str(&format!("  {} enter chain {} ({})\n", p.cyan("=>"), chain, via));
            }
            Match {
                chain,
                rule_index,
                text,
                action,
                assumed,
            } => {
                out.push_str(&format!(
                    "  {} [{}] rule #{}: {}\n       -> {}\n",
                    p.cyan("**"),
                    chain,
                    rule_index,
                    text,
                    p.bold(action)
                ));
                if !assumed.is_empty() {
                    out.push_str(&format!(
                        "       {} assumed true: {}\n",
                        p.yellow("??"),
                        assumed.join(", ")
                    ));
                }
            }
            ChainEnd { chain } => {
                out.push_str(&format!("  -- end of chain {chain}\n"));
            }
            Return { from, to } => {
                out.push_str(&format!(
                    "  {} RETURN from {}{}\n",
                    p.cyan("<="),
                    from,
                    to.as_deref().map(|t| format!(" to {t}")).unwrap_or_else(|| " (no caller)".into())
                ));
            }
            Policy { chain, policy } => {
                out.push_str(&format!("  {} chain {chain} policy: {}\n", p.cyan("!!"), p.bold(policy)));
            }
            Verdict { target } => {
                out.push_str(&format!("  {} final verdict: {}\n", p.cyan("=="), p.bold(target)));
            }
            LoopDetected { note } => {
                out.push_str(&format!("  {}\n", p.red(&format!("LOOP: {note}"))));
            }
        }
    }
    match &trace.verdict {
        Some(v) => out.push_str(&format!("Verdict: {}\n", p.bold(v))),
        None => out.push_str("Verdict: undetermined (no terminal verdict reached)\n"),
    }
    print!("{out}");

    if let Some(dest) = &a.json {
        let mut root = J::obj();
        root.put("backend", J::str(rs.backend.name()));
        root.put("table", J::str(&a.table));
        root.put("start_chain", J::str(&a.chain));
        let mut pk = J::obj();
        pk.put("src", J::str(src_s));
        pk.put("dst", J::str(dst_s));
        pk.put("proto", J::str(rect::proto_display(proto)));
        pk.put("sport", J::Num(a.sport as u64));
        pk.put("dport", J::Num(a.dport as u64));
        root.put("packet", pk);
        root.put(
            "events",
            J::arr(trace.events.iter().map(|e| {
                use simulate::Event::*;
                let mut o = J::obj();
                match e {
                    EnterChain { chain, via } => {
                        o.put("event", J::str("enter_chain"));
                        o.put("chain", J::str(chain));
                        o.put("via", J::str(via));
                    }
                    Match {
                        chain,
                        rule_index,
                        text,
                        action,
                        assumed,
                    } => {
                        o.put("event", J::str("match"));
                        o.put("chain", J::str(chain));
                        o.put("rule", J::Num(*rule_index as u64));
                        o.put("text", J::str(text));
                        o.put("action", J::str(action));
                        o.put("assumed", J::arr(assumed.iter().map(|x| J::str(x))));
                    }
                    ChainEnd { chain } => {
                        o.put("event", J::str("chain_end"));
                        o.put("chain", J::str(chain));
                    }
                    Return { from, to } => {
                        o.put("event", J::str("return"));
                        o.put("from", J::str(from));
                        o.put("to", to.as_deref().map(J::str).unwrap_or(J::Null));
                    }
                    Policy { chain, policy } => {
                        o.put("event", J::str("policy"));
                        o.put("chain", J::str(chain));
                        o.put("policy", J::str(policy));
                    }
                    Verdict { target } => {
                        o.put("event", J::str("verdict"));
                        o.put("target", J::str(target));
                    }
                    LoopDetected { note } => {
                        o.put("event", J::str("loop_detected"));
                        o.put("note", J::str(note));
                    }
                }
                o
            })),
        );
        root.put(
            "verdict",
            trace.verdict.as_deref().map(J::str).unwrap_or(J::Null),
        );
        let payload = json::render(&root);
        match dest {
            Some(path) => std::fs::write(path, payload).map_err(|e| format!("writing {path}: {e}"))?,
            None => println!("{payload}"),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let result = match args.cmd.as_str() {
        "analyze" => cmd_analyze(&args),
        "simulate" => cmd_simulate(&args),
        _ => unreachable!(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::io::stderr().flush().ok();
            ExitCode::FAILURE
        }
    }
}
