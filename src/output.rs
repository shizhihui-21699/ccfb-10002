//! 终端文本输出与 JSON 导出（零外部依赖，手写 JSON 转义）。

use crate::analyze::*;
use crate::intervals::IntervalSet;
use crate::ip::{format_ip, Family};
use crate::model::*;
use crate::simulate::SimulationResult;

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn describe_intervals(set: &IntervalSet, family: Family, is_ip: bool) -> Vec<String> {
    set.describe(|v| {
        if is_ip {
            format_ip(family, v)
        } else {
            v.to_string()
        }
    })
}

fn proto_name(v: u128) -> String {
    match v as u8 {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        58 => "icmpv6".to_string(),
        47 => "gre".to_string(),
        50 => "esp".to_string(),
        51 => "ah".to_string(),
        132 => "sctp".to_string(),
        n => n.to_string(),
    }
}

fn state_name(v: u128) -> String {
    match v {
        0 => "NEW".to_string(),
        1 => "ESTABLISHED".to_string(),
        2 => "RELATED".to_string(),
        3 => "UNTRACKED".to_string(),
        4 => "INVALID".to_string(),
        n => n.to_string(),
    }
}

/// 描述一个 MatchSet 相对全集收窄了的字段。
pub fn describe_match(m: &MatchSet, family: Family) -> Vec<(String, String)> {
    let uni = MatchSet::universe(family);
    let mut out = Vec::new();

    let push_ip = |out: &mut Vec<(String, String)>, name: &str,
                   cur: &IntervalSet, full: &IntervalSet| {
        if cur != full {
            out.push((
                name.to_string(),
                describe_intervals(cur, family, true).join(","),
            ));
        }
    };
    push_ip(&mut out, "src_ip", &m.src_ip, &uni.src_ip);
    push_ip(&mut out, "dst_ip", &m.dst_ip, &uni.dst_ip);

    if m.proto != uni.proto {
        out.push((
            "proto".to_string(),
            m.proto.describe(proto_name).join(","),
        ));
    }
    if m.src_port != uni.src_port {
        out.push((
            "src_port".to_string(),
            describe_intervals(&m.src_port, family, false).join(","),
        ));
    }
    if m.dst_port != uni.dst_port {
        out.push((
            "dst_port".to_string(),
            describe_intervals(&m.dst_port, family, false).join(","),
        ));
    }
    if m.icmp_type != uni.icmp_type {
        out.push((
            "icmp_type".to_string(),
            describe_intervals(&m.icmp_type, family, false).join(","),
        ));
    }
    if m.state != uni.state {
        out.push((
            "state".to_string(),
            m.state.describe(state_name).join(","),
        ));
    }
    if m.iif != uni.iif {
        out.push(("iif".to_string(), m.iif.describe()));
    }
    if m.oif != uni.oif {
        out.push(("oif".to_string(), m.oif.describe()));
    }
    out
}

fn rule_line(ruleset: &Ruleset, id: &RuleId) -> String {
    match ruleset.get_rule(id) {
        Some(r) => format!("[{}:{}] {}", r.file, r.line_no, r.raw),
        None => format!("{id}（规则不存在）"),
    }
}

pub fn print_text(ruleset: &Ruleset, report: &AnalysisReport) {
    let total_shadow: usize = report.chains.iter().map(|c| c.shadowed.len()).sum();
    let total_red: usize = report.chains.iter().map(|c| c.redundant.len()).sum();
    let total_conf: usize = report.chains.iter().map(|c| c.conflicts.len()).sum();

    println!("════════════════════════════════════════════════════════════");
    println!(" 防火墙规则分析报告（精确区间运算，无抽样）");
    println!(" 遮蔽规则: {total_shadow}  冗余规则: {total_red}  冲突对: {total_conf}");
    if !report.dangling_jumps.is_empty() {
        println!(" 悬空跳转: {}", report.dangling_jumps.len());
    }
    println!("════════════════════════════════════════════════════════════");

    for cr in &report.chains {
        let table = ruleset.table(&cr.table).unwrap();
        let family = table.family;
        let chain = table.chain(&cr.chain).unwrap();
        let policy = chain
            .policy
            .clone()
            .map(|p| format!(" policy={p}"))
            .unwrap_or_default();
        let hook = chain
            .hook
            .clone()
            .map(|h| format!(" hook={h}"))
            .unwrap_or_default();
        let unreach = if cr.unreachable { "  [不可达链]" } else { "" };
        let terminal = report
            .always_terminal
            .get(&cr.table)
            .and_then(|m| m.get(&cr.chain))
            .copied()
            .unwrap_or(false)
            .then_some(" [必然终结]")
            .unwrap_or("");

        println!();
        println!("▶ 链 {}/{}（{} 条规则{policy}{hook}）{terminal}{unreach}",
            cr.table, cr.chain, chain.rules.len());

        if cr.shadowed.is_empty() && cr.redundant.is_empty() && cr.conflicts.is_empty() {
            println!("   ✓ 未发现问题");
            continue;
        }

        for f in &cr.shadowed {
            println!("   [遮蔽] 规则 {} 永远不会被求值", f.rule);
            println!("          {}", rule_line(ruleset, &f.rule));
            if let Some(s) = &f.by_single {
                println!("          被单条规则完全遮蔽: {s}");
                println!("          ↑ {}", rule_line(ruleset, s));
            } else {
                println!("          由以下 {} 条规则联合遮蔽（任一包必在其中一条被终结）:",
                    f.by_combination.len());
                for sid in &f.by_combination {
                    println!("            - {sid}  {}", rule_line(ruleset, sid));
                }
            }
        }

        for f in &cr.redundant {
            match &f.reason {
                RedundantReason::EmptyMatch => {
                    println!("   [冗余] 规则 {} 匹配条件自相矛盾，匹配空间为空", f.rule);
                    println!("          {}", rule_line(ruleset, &f.rule));
                }
                RedundantReason::DuplicateOf(prev) => {
                    println!("   [冗余] 规则 {} 与 {prev} 的匹配空间完全相同", f.rule);
                    println!("          {}", rule_line(ruleset, &f.rule));
                    println!("          ↑ {}", rule_line(ruleset, prev));
                }
            }
        }

        for f in &cr.conflicts {
            println!(
                "   [冲突] {} 与 {} 在同一报文范围内动作不一致",
                f.first, f.second
            );
            println!("          规则A: {}", rule_line(ruleset, &f.first));
            println!("          规则B: {}", rule_line(ruleset, &f.second));
            let fields = describe_match(&f.intersection, family);
            if fields.is_empty() {
                println!("          冲突范围: 全部报文");
            } else {
                println!("          冲突范围（精确交集）:");
                for (k, v) in fields {
                    println!("            {k}: {v}");
                }
            }
        }
    }

    if !report.dangling_jumps.is_empty() {
        println!();
        println!("▶ 悬空跳转（目标链不存在）:");
        for (id, target) in &report.dangling_jumps {
            println!("   {id} -> {target}");
            println!("     {}", rule_line(ruleset, id));
        }
    }
}

fn match_to_json(m: &MatchSet, family: Family) -> String {
    let iv = |s: &IntervalSet, ip: bool| -> String {
        let parts: Vec<String> = s
            .ranges()
            .iter()
            .map(|&(lo, hi)| {
                let a = if ip { format_ip(family, lo) } else { lo.to_string() };
                let b = if ip { format_ip(family, hi) } else { hi.to_string() };
                if lo == hi {
                    format!("\"{a}\"")
                } else {
                    format!("{{\"lo\":\"{a}\",\"hi\":\"{b}\"}}")
                }
            })
            .collect();
        format!("[{}]", parts.join(","))
    };
    format!(
        "{{\"src_ip\":{src},\"dst_ip\":{dst},\"proto\":{proto},\"src_port\":{sp},\
\"dst_port\":{dp},\"icmp_type\":{icmp},\"state\":{st},\"iif\":\"{iif}\",\"oif\":\"{oif}\"}}",
        src = iv(&m.src_ip, true),
        dst = iv(&m.dst_ip, true),
        proto = iv(&m.proto, false),
        sp = iv(&m.src_port, false),
        dp = iv(&m.dst_port, false),
        icmp = iv(&m.icmp_type, false),
        st = iv(&m.state, false),
        iif = json_escape(&m.iif.describe()),
        oif = json_escape(&m.oif.describe()),
    )
}

fn rule_json(ruleset: &Ruleset, id: &RuleId) -> String {
    match ruleset.get_rule(id) {
        Some(r) => format!(
            "{{\"id\":\"{id}\",\"file\":\"{file}\",\"line\":{line},\"raw\":\"{raw}\",\
\"verdict\":\"{verdict}\"}}",
            id = json_escape(&id.to_string()),
            file = json_escape(&r.file),
            line = r.line_no,
            raw = json_escape(&r.raw),
            verdict = json_escape(&r.verdict.raw),
        ),
        None => format!("{{\"id\":\"{}\"}}", json_escape(&id.to_string())),
    }
}

pub fn print_json(ruleset: &Ruleset, report: &AnalysisReport) -> String {
    let mut s = String::new();
    s.push_str("{\"tool\":\"fwanalyze\",\"summary\":{");
    let sh: usize = report.chains.iter().map(|c| c.shadowed.len()).sum();
    let rd: usize = report.chains.iter().map(|c| c.redundant.len()).sum();
    let cf: usize = report.chains.iter().map(|c| c.conflicts.len()).sum();
    s.push_str(&format!(
        "\"shadowed\":{sh},\"redundant\":{rd},\"conflicts\":{cf},\
\"dangling_jumps\":{dj}}},",
        dj = report.dangling_jumps.len()
    ));

    s.push_str("\"chains\":[");
    let mut chain_jsons = Vec::new();
    for cr in &report.chains {
        let family = ruleset.table(&cr.table).unwrap().family;
        let mut c = String::new();
        c.push_str(&format!(
            "{{\"table\":\"{}\",\"chain\":\"{}\",\"unreachable\":{},",
            json_escape(&cr.table),
            json_escape(&cr.chain),
            cr.unreachable
        ));

        c.push_str("\"shadowed\":[");
        c.push_str(
            &cr.shadowed
                .iter()
                .map(|f| {
                    format!(
                        "{{\"rule\":{rule},\"by_single\":{single},\"by_combination\":[{comb}]}}",
                        rule = rule_json(ruleset, &f.rule),
                        single = match &f.by_single {
                            Some(id) => rule_json(ruleset, id),
                            None => "null".to_string(),
                        },
                        comb = f
                            .by_combination
                            .iter()
                            .map(|id| rule_json(ruleset, id))
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        c.push_str("],\"redundant\":[");
        c.push_str(
            &cr.redundant
                .iter()
                .map(|f| {
                    let (reason, extra) = match &f.reason {
                        RedundantReason::EmptyMatch => {
                            ("\"empty_match\"", "null".to_string())
                        }
                        RedundantReason::DuplicateOf(id) => {
                            ("\"duplicate\"", rule_json(ruleset, id))
                        }
                    };
                    format!(
                        "{{\"rule\":{rule},\"reason\":{reason},\"duplicate_of\":{extra}}}",
                        rule = rule_json(ruleset, &f.rule),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        c.push_str("],\"conflicts\":[");
        c.push_str(
            &cr.conflicts
                .iter()
                .map(|f| {
                    format!(
                        "{{\"first\":{a},\"second\":{b},\"intersection\":{inter}}}",
                        a = rule_json(ruleset, &f.first),
                        b = rule_json(ruleset, &f.second),
                        inter = match_to_json(&f.intersection, family),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        c.push_str("]}");
        chain_jsons.push(c);
    }
    s.push_str(&chain_jsons.join(","));
    s.push_str("],");

    s.push_str("\"dangling_jumps\":[");
    s.push_str(
        &report
            .dangling_jumps
            .iter()
            .map(|(id, target)| {
                format!(
                    "{{\"rule\":{rule},\"target\":\"{target}\"}}",
                    rule = rule_json(ruleset, id),
                    target = json_escape(target),
                )
            })
            .collect::<Vec<_>>()
            .join(","),
    );
    s.push_str("],");

    s.push_str("\"warnings\":[");
    s.push_str(
        &ruleset
            .warnings
            .iter()
            .map(|w| format!("\"{}\"", json_escape(w)))
            .collect::<Vec<_>>()
            .join(","),
    );
    s.push_str("]}");
    s
}

pub fn print_simulation(pkt: &crate::simulate::Packet, res: &SimulationResult) {
    println!("════════════════════════════════════════════════════════════");
    println!(" 报文模拟");
    println!(
        " 五元组: {}:{} -> {}:{} proto={}",
        pkt.src_ip.format(),
        pkt.src_port,
        pkt.dst_ip.format(),
        pkt.dst_port,
        proto_name(pkt.proto as u128),
    );
    if !pkt.iif.is_empty() {
        print!(" iif={}", pkt.iif);
    }
    if !pkt.oif.is_empty() {
        print!(" oif={}", pkt.oif);
    }
    if let Some(t) = pkt.icmp_type {
        print!(" icmp_type={t}");
    }
    if let Some(s) = pkt.state {
        print!(" state={}", conn_state_name(s));
    }
    println!();
    println!("════════════════════════════════════════════════════════════");

    for (i, step) in res.steps.iter().enumerate() {
        println!(
            "跳 {i}: 进入链 {}:{}，求值规则序号 {:?}",
            step.table, step.chain, step.evaluated
        );
        if let Some((idx, action)) = &step.hit {
            println!("        命中规则 #{idx}: {action}");
        } else {
            println!("        无规则命中");
        }
        println!("        结果: {}", step.outcome);
    }

    if let Some(e) = &res.error {
        println!("错误: {e}");
    }
    if res.loop_detected {
        println!("警告: 检测到跳转环");
    }
    println!("────────────────────────────────────────────────────────────");
    println!("最终判定: {}", res.final_verdict);
}

pub fn simulation_json(pkt: &crate::simulate::Packet, res: &SimulationResult) -> String {
    let steps = res
        .steps
        .iter()
        .map(|s| {
            format!(
                "{{\"table\":\"{t}\",\"chain\":\"{c}\",\"evaluated\":[{ev}],\
\"hit\":{hit},\"outcome\":\"{out}\"}}",
                t = json_escape(&s.table),
                c = json_escape(&s.chain),
                ev = s
                    .evaluated
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                hit = match &s.hit {
                    Some((idx, action)) => format!(
                        "{{\"index\":{idx},\"action\":\"{}\"}}",
                        json_escape(action)
                    ),
                    None => "null".to_string(),
                },
                out = json_escape(&s.outcome),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"packet\":{{\"src_ip\":\"{sip}\",\"dst_ip\":\"{dip}\",\"proto\":{proto},\
\"src_port\":{sp},\"dst_port\":{dp},\"iif\":\"{iif}\",\"oif\":\"{oif}\"}},
\"final_verdict\":\"{fv}\",\"loop_detected\":{lp},\"error\":{err},\"steps\":[{steps}]}}",
        sip = json_escape(&pkt.src_ip.format()),
        dip = json_escape(&pkt.dst_ip.format()),
        proto = pkt.proto,
        sp = pkt.src_port,
        dp = pkt.dst_port,
        iif = json_escape(&pkt.iif),
        oif = json_escape(&pkt.oif),
        fv = json_escape(&res.final_verdict),
        lp = res.loop_detected,
        err = res.error.as_ref().map(|e| format!("\"{}\"", json_escape(e))).unwrap_or_else(|| "null".to_string()),
    )
}
