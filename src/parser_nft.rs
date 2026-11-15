//! nftables `nft list ruleset` 导出解析器。
//!
//! 支持：
//!   table inet filter { ... }
//!     chain input { type filter hook input priority filter; policy drop; }
//!     ip saddr { 10.0.0.0/8, 192.168.0.0/16 } tcp dport != 22 jump block
//! 命名 set 定义（type ipv4_addr / inet_service）会被解析并在引用处展开。

use crate::intervals::IntervalSet;
use crate::ip::{Family, IpNet};
use crate::model::*;
use std::collections::HashMap;

/// 已定义的命名 set：按元素类型保存原始字符串。
#[derive(Debug, Clone, Default)]
struct NftSets {
    // key: (table, set 名)
    ip_sets: HashMap<(String, String), Vec<IpNet>>,
    port_sets: HashMap<(String, String), Vec<String>>,
}

/// 词法切分：引号内整体成词；{} , 单独成词；# 之后为注释。
fn tokenize_nft(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' => i += 1,
            '#' => break,
            '{' | '}' | ',' => {
                out.push(chars[i].to_string());
                i += 1;
            }
            '"' | '\'' => {
                let q = chars[i];
                i += 1;
                let mut buf = String::new();
                while i < chars.len() && chars[i] != q {
                    buf.push(chars[i]);
                    i += 1;
                }
                i += 1;
                out.push(buf);
            }
            _ => {
                let mut buf = String::new();
                while i < chars.len()
                    && !matches!(chars[i], ' ' | '\t' | '{' | '}' | ',' | '#')
                {
                    buf.push(chars[i]);
                    i += 1;
                }
                out.push(buf);
            }
        }
    }
    out
}

struct NftBuilder {
    ms: MatchSet,
    unsupported: Vec<String>,
}

impl NftBuilder {
    fn new(family: Family) -> Self {
        NftBuilder {
            ms: MatchSet::universe(family),
            unsupported: Vec::new(),
        }
    }

    fn ip_field(&mut self, field: &str, elems: &[IpNet], negated: bool) -> Result<(), String> {
        let fam = self.ms.family;
        let mut s = IntervalSet::new();
        for n in elems {
            if n.family() != fam {
                return Err(format!("地址族与表不一致: {n}"));
            }
            let (lo, hi) = n.range();
            s = s.union(&IntervalSet::range(lo, hi));
        }
        if negated {
            s = IntervalSet::universe(fam.max_value()).subtract(&s);
        }
        match field {
            "saddr" => self.ms.src_ip = self.ms.src_ip.intersect(&s),
            "daddr" => self.ms.dst_ip = self.ms.dst_ip.intersect(&s),
            _ => unreachable!(),
        }
        Ok(())
    }

    fn port_field(&mut self, field: &str, elems: &[String], negated: bool) -> Result<(), String> {
        let mut s = IntervalSet::new();
        for e in elems {
            s = s.union(&parse_port(e)?);
        }
        if negated {
            s = IntervalSet::universe(65535).subtract(&s);
        }
        match field {
            "sport" => self.ms.src_port = self.ms.src_port.intersect(&s),
            "dport" => self.ms.dst_port = self.ms.dst_port.intersect(&s),
            _ => unreachable!(),
        }
        Ok(())
    }

    fn proto(&mut self, val: &str, negated: bool) -> Result<(), String> {
        let num = proto_num(val)?;
        let mut s = IntervalSet::point(num as u128);
        if negated {
            s = IntervalSet::universe(255).subtract(&s);
        }
        self.ms.proto = self.ms.proto.intersect(&s);
        Ok(())
    }

    fn icmp(&mut self, val: &str, negated: bool) -> Result<(), String> {
        let t: u128 = match val.parse() {
            Ok(v) if v <= 255 => v,
            _ => {
                let name = val.to_ascii_lowercase();
                let known: HashMap<&str, u8> = [
                    ("echo-reply", 0),
                    ("destination-unreachable", 3),
                    ("echo-request", 8),
                    ("time-exceeded", 11),
                ]
                .into_iter()
                .collect();
                *known
                    .get(name.as_str())
                    .ok_or_else(|| format!("未知 ICMP 类型: {val}"))? as u128
            }
        };
        let mut s = IntervalSet::point(t);
        if negated {
            s = IntervalSet::universe(255).subtract(&s);
        }
        self.ms.icmp_type = self.ms.icmp_type.intersect(&s);
        Ok(())
    }

    fn states(&mut self, val: &str, negated: bool) -> Result<(), String> {
        let mut s = IntervalSet::new();
        for part in val.split(',') {
            let st = parse_conn_state(part.trim())
                .ok_or_else(|| format!("未知 conntrack 状态: {part}"))?;
            s = s.union(&IntervalSet::point(st as u128));
        }
        if negated {
            s = IntervalSet::universe(4).subtract(&s);
        }
        self.ms.state = self.ms.state.intersect(&s);
        Ok(())
    }

    fn iface(&mut self, field: &str, val: &str, negated: bool) {
        let p = IfacePred::from_pat(val.to_string(), negated);
        match field {
            "iifname" => self.ms.iif = self.ms.iif.intersect(&p),
            "oifname" => self.ms.oif = self.ms.oif.intersect(&p),
            _ => unreachable!(),
        }
    }
}

fn parse_port(spec: &str) -> Result<IntervalSet, String> {
    if let Some((a, b)) = spec.split_once('-') {
        let lo: u128 = a.parse().map_err(|_| format!("非法端口: {a}"))?;
        let hi: u128 = b.parse().map_err(|_| format!("非法端口: {b}"))?;
        if lo > hi || hi > 65535 {
            return Err(format!("非法端口段: {spec}"));
        }
        Ok(IntervalSet::range(lo, hi))
    } else {
        let v: u128 = spec.parse().map_err(|_| format!("非法端口: {spec}"))?;
        if v > 65535 {
            return Err(format!("端口超出范围: {spec}"));
        }
        Ok(IntervalSet::point(v))
    }
}

fn proto_num(val: &str) -> Result<u8, String> {
    Ok(match val.to_ascii_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "sctp" => 132,
        other => other.parse::<u8>().map_err(|_| format!("未知协议: {val}"))?,
    })
}

pub fn parse_nft_ruleset(input: &str, file: &str, ruleset: &mut Ruleset) -> Result<(), String> {
    let sets = collect_sets(input, file, ruleset)?;
    let mut current_table: Option<(String, Family)> = None;
    let mut current_chain: Option<String> = None;
    let mut table_depth = 0i32;
    let mut in_set_block = false;
    let mut set_depth = 0i32;

    // 计算一行的大括号净增量；引号内的大括号（接口名等）不计。
    let brace_delta = |t: &str| -> i32 {
        let mut d = 0i32;
        let mut in_q = None;
        for c in t.chars() {
            if let Some(q) = in_q {
                if c == q {
                    in_q = None;
                }
            } else if c == '"' || c == '\'' {
                in_q = Some(c);
            } else if c == '{' {
                d += 1;
            } else if c == '}' {
                d -= 1;
            }
        }
        d
    };

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // set/map 块：整体跳过内容，靠大括号深度识别块结束
        if in_set_block {
            set_depth += brace_delta(trimmed);
            if set_depth <= 0 {
                in_set_block = false;
            }
            continue;
        }

        // 表声明：table inet filter {
        if let Some(rest) = trimmed.strip_prefix("table ") {
            let tokens = tokenize_nft(rest);
            if tokens.len() < 2 {
                return Err(format!("{file}:{line_no}: 非法 table 声明: {trimmed}"));
            }
            let fam = match tokens[0].as_str() {
                "ip" => Family::V4,
                "ip6" => Family::V6,
                "inet" => Family::V4, // 混合族：规则中出现 v6 再升级
                other => {
                    ruleset
                        .warnings
                        .push(format!("{file}:{line_no}: 未知表族 {other}，按 ip 处理"));
                    Family::V4
                }
            };
            let tname = tokens[1].clone();
            current_table = Some((tname.clone(), fam));
            table_depth = brace_delta(trimmed).max(1);
            current_chain = None;
            if ruleset.table_mut(&tname).is_none() {
                ruleset.tables.push(Table {
                    name: tname,
                    family: fam,
                    chains: Vec::new(),
                });
            }
            continue;
        }

        if current_table.is_none() {
            // 表外的杂项（flush ruleset 等）忽略
            continue;
        }

        if trimmed.starts_with("set ") || trimmed.starts_with("map ") {
            in_set_block = true;
            set_depth = brace_delta(trimmed);
            if set_depth <= 0 {
                in_set_block = false;
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("chain ") {
            let tokens = tokenize_nft(rest);
            if tokens.is_empty() {
                return Err(format!("{file}:{line_no}: 非法 chain 声明: {trimmed}"));
            }
            let cname = tokens[0].clone();
            let (tname, _fam) = current_table.clone().unwrap();
            let table = ruleset.table_mut(&tname).unwrap();
            if table.chain_mut(&cname).is_none() {
                table.chains.push(Chain {
                    name: cname.clone(),
                    policy: None,
                    counters: (0, 0),
                    hook: None,
                    rules: Vec::new(),
                });
            }
            current_chain = Some(cname);
            table_depth += brace_delta(trimmed);
            continue;
        }

        // 纯闭合括号：结束链或表
        if trimmed.starts_with('}') {
            let d = brace_delta(trimmed);
            table_depth += d;
            // 无法仅凭括号区分链尾与表尾：用是否在链中判断
            if current_chain.is_some() {
                // 若这一行让深度回到表的基准（1），则是链尾；
                // 若回到 0，则整个表结束。
                if table_depth <= 0 {
                    current_chain = None;
                    current_table = None;
                    table_depth = 0;
                } else {
                    current_chain = None;
                }
            } else if table_depth <= 0 {
                current_table = None;
                table_depth = 0;
            }
            continue;
        }

        // 链属性行：type filter hook input priority filter; policy drop;
        if trimmed.starts_with("type ") {
            if let Some(cname) = current_chain.clone() {
                let (tname, _) = current_table.clone().unwrap();
                let table = ruleset.table_mut(&tname).unwrap();
                let chain = table.chain_mut(&cname).unwrap();
                let lower = trimmed.to_ascii_lowercase();
                if let Some(pos) = lower.find("policy ") {
                    let pol = trimmed[pos + 7..]
                        .trim()
                        .trim_end_matches(';')
                        .split_whitespace()
                        .next()
                        .map(|s| s.to_ascii_uppercase());
                    chain.policy = pol;
                }
                if let Some(hook_pos) = lower.find("hook ") {
                    let hook = trimmed[hook_pos + 5..]
                        .trim_end_matches(';')
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    chain.hook = Some(hook);
                }
            }
            continue;
        }

        // 规则行：位于某个链内，且不是块声明（声明类已在上面处理）
        if current_chain.is_some() {
            let (tname, fam) = current_table.clone().unwrap();
            let cname = current_chain.clone().unwrap();
            let rule = parse_nft_rule(trimmed, file, line_no, &tname, &cname, fam, &sets)?;
            let table = ruleset.table_mut(&tname).unwrap();
            if rule.matches.family == Family::V6 {
                table.family = Family::V6;
            }
            let chain = table.chain_mut(&cname).unwrap();
            let mut rule = rule;
            rule.id.index = chain.rules.len();
            chain.rules.push(rule);
            // 规则行内的内联集合 { ... } 大括号是平衡的，净增量应为 0
            table_depth += brace_delta(trimmed);
        }
    }
    Ok(())
}

/// 预扫描所有 set/map 定义，提取地址集与端口集。
fn collect_sets(
    input: &str,
    file: &str,
    _ruleset: &mut Ruleset,
) -> Result<NftSets, String> {
    let mut sets = NftSets::default();
    let mut table = String::new();
    let mut in_set = false;
    let mut set_name = String::new();
    let mut set_type = String::new();
    let mut elems_buf = Vec::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if let Some(rest) = trimmed.strip_prefix("table ") {
            let tokens = tokenize_nft(rest);
            if tokens.len() >= 2 {
                table = tokens[1].clone();
            }
            continue;
        }
        if trimmed.starts_with("set ") || trimmed.starts_with("map ") {
            let tokens = tokenize_nft(trimmed);
            set_name = tokens.get(1).cloned().unwrap_or_default();
            in_set = true;
            set_type = String::new();
            elems_buf = Vec::new();
            continue;
        }
        if in_set {
            if let Some(rest) = trimmed.strip_prefix("type ") {
                set_type = rest.trim_end_matches(';').trim().to_string();
                continue;
            }
            if trimmed.starts_with("elements=") || trimmed.starts_with("elements =") {
                let tokens = tokenize_nft(trimmed);
                let mut collecting = false;
                for t in &tokens {
                    if t == "{" {
                        collecting = true;
                        continue;
                    }
                    if t == "}" {
                        collecting = false;
                        continue;
                    }
                    if collecting && t != "," {
                        elems_buf.push(t.clone());
                    }
                }
            }
            if trimmed == "}" {
                flush_set(&mut sets, &table, &set_name, &set_type, &elems_buf, file, line_no)?;
                in_set = false;
            }
        }
    }
    Ok(sets)
}

fn flush_set(
    sets: &mut NftSets,
    table: &str,
    name: &str,
    set_type: &str,
    elems: &[String],
    file: &str,
    line_no: usize,
) -> Result<(), String> {
    if set_type.contains("ipv4_addr") || set_type.contains("ipv6_addr") || set_type.contains("ether_addr") {
        if set_type.contains("ether_addr") {
            return Ok(()); // MAC 集不参与本工具建模
        }
        let mut nets = Vec::new();
        for e in elems {
            nets.push(IpNet::parse(e).map_err(|err| format!("{file}:{line_no}: {err}"))?);
        }
        sets.ip_sets.insert((table.to_string(), name.to_string()), nets);
    } else if set_type.contains("inet_service") || set_type.contains("inet_proto") {
        sets.port_sets
            .insert((table.to_string(), name.to_string()), elems.to_vec());
    }
    Ok(())
}

fn parse_nft_rule(
    line: &str,
    file: &str,
    line_no: usize,
    table: &str,
    chain: &str,
    family: Family,
    sets: &NftSets,
) -> Result<Rule, String> {
    let tokens = tokenize_nft(line);
    let mut b = NftBuilder::new(family);
    let mut verdict = Verdict {
        kind: VerdictKind::Unknown,
        target: None,
        detail: None,
        raw: "<无动作>".to_string(),
    };
    let mut i = 0;

    // 读取一个值或一个 { ... } 集合，返回原始元素 token 列表。
    fn read_value_tokens(tokens: &[String], i: &mut usize) -> (bool, Vec<String>) {
        let mut neg = false;
        if *i < tokens.len() && (tokens[*i] == "!=" || tokens[*i] == "!") {
            neg = true;
            *i += 1;
        } else if *i < tokens.len() && tokens[*i] == "==" {
            *i += 1;
        }
        if *i < tokens.len() && tokens[*i] == "@" {
            *i += 1;
            let name = tokens.get(*i).cloned().unwrap_or_default();
            *i += 1;
            return (neg, vec!["@".to_string() + &name]);
        }
        if *i < tokens.len() && tokens[*i] == "{" {
            *i += 1;
            let mut elems = Vec::new();
            while *i < tokens.len() && tokens[*i] != "}" {
                if tokens[*i] != "," {
                    elems.push(tokens[*i].clone());
                }
                *i += 1;
            }
            if *i < tokens.len() {
                *i += 1; // }
            }
            (neg, elems)
        } else if *i < tokens.len() {
            let v = tokens[*i].clone();
            *i += 1;
            (neg, vec![v])
        } else {
            (neg, vec![])
        }
    }

    let resolve_ip_elems = |elems: &[String], t: &str, s: &NftSets| -> Result<Vec<IpNet>, String> {
        if elems.len() == 1 && let Some(name) = elems[0].strip_prefix('@') {
            s.ip_sets
                .get(&(t.to_string(), name.to_string()))
                .cloned()
                .ok_or_else(|| format!("{file}:{line_no}: 未定义的地址集 @{name}"))
        } else {
            elems.iter().map(|e| IpNet::parse(e)).collect()
        }
    };

    let resolve_port_elems =
        |elems: &[String], t: &str, s: &NftSets| -> Result<Vec<String>, String> {
            if elems.len() == 1 && let Some(name) = elems[0].strip_prefix('@') {
                s.port_sets
                    .get(&(t.to_string(), name.to_string()))
                    .cloned()
                    .ok_or_else(|| format!("{file}:{line_no}: 未定义的端口集 @{name}"))
            } else {
                Ok(elems.to_vec())
            }
        };

    while i < tokens.len() {
        let tok = tokens[i].clone();
        match tok.as_str() {
            // 地址族前缀
            "ip" | "ip6" => {
                i += 1;
                let field = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                let (neg, elems) = read_value_tokens(&tokens, &mut i);
                match field.as_str() {
                    "saddr" | "daddr" => {
                        let nets = resolve_ip_elems(&elems, table, sets)?;
                        b.ip_field(&field, &nets, neg)
                            .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                    }
                    "protocol" => {
                        let neg2 = neg;
                        for v in &elems {
                            b.proto(v, neg2)
                                .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                        }
                    }
                    _ => {
                        b.unsupported.push(format!("{tok} {field}（按匹配所有处理）"));
                    }
                }
            }
            "meta" => {
                i += 1;
                let key = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                match key.as_str() {
                    "l4proto" => {
                        let (neg, elems) = read_value_tokens(&tokens, &mut i);
                        for v in &elems {
                            b.proto(v, neg)
                                .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                        }
                    }
                    "mark" | "priority" | "iif" | "oif" | "nftrace" | "rtclassid" | "cgroup"
                    | "skgid" | "skuid" => {
                        // iif/oif 是接口索引（数字），与 iifname 不同，保守忽略
                        let (_, elems) = read_value_tokens(&tokens, &mut i);
                        if !elems.is_empty() {
                            b.unsupported
                                .push(format!("meta {key}（按匹配所有处理）"));
                        }
                    }
                    _ => {
                        let (_, elems) = read_value_tokens(&tokens, &mut i);
                        if !elems.is_empty() {
                            b.unsupported
                                .push(format!("meta {key}（按匹配所有处理）"));
                        }
                    }
                }
            }
            "tcp" | "udp" | "udplite" | "sctp" | "th" => {
                // tcp dport 22 / th sport { 123, 456 }
                let proto_tok = tok.clone();
                i += 1;
                let field = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                let (neg, elems) = read_value_tokens(&tokens, &mut i);
                match field.as_str() {
                    "sport" | "dport" => {
                        if proto_tok != "th" {
                            // 协议名本身同时约束 l4proto
                            b.proto(&proto_tok, false)
                                .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                        }
                        let ports = resolve_port_elems(&elems, table, sets)?;
                        b.port_field(&field, &ports, neg)
                            .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                    }
                    _ => {
                        b.unsupported
                            .push(format!("{proto_tok} {field}（按匹配所有处理）"));
                    }
                }
            }
            "icmp" | "icmpv6" => {
                i += 1;
                let key = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                if key == "type" {
                    let (neg, elems) = read_value_tokens(&tokens, &mut i);
                    for v in &elems {
                        b.icmp(v, neg)
                            .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                    }
                } else {
                    b.unsupported.push(format!("icmp {key}（按匹配所有处理）"));
                }
            }
            "iifname" | "oifname" => {
                i += 1;
                let (neg, elems) = read_value_tokens(&tokens, &mut i);
                for v in &elems {
                    b.iface(&tok, v, neg);
                }
            }
            "ct" => {
                i += 1;
                let key = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                if key == "state" {
                    let (neg, elems) = read_value_tokens(&tokens, &mut i);
                    b.states(&elems.join(","), neg)
                        .map_err(|e| format!("{file}:{line_no}: {e}"))?;
                } else {
                    let (_, elems) = read_value_tokens(&tokens, &mut i);
                    if !elems.is_empty() {
                        b.unsupported
                            .push(format!("ct {key}（按匹配所有处理）"));
                    }
                }
            }
            "accept" | "drop" | "reject" | "queue" | "return" => {
                // make_verdict 从当前判定 token 开始，先让它消费掉该 token
                i += 1;
                verdict = make_verdict(&tok, &tokens, &mut i);
            }
            "jump" | "goto" => {
                let kind = if tok == "jump" {
                    VerdictKind::Jump
                } else {
                    VerdictKind::Goto
                };
                i += 1;
                let target = tokens.get(i).cloned().unwrap_or_default();
                i += 1;
                verdict = Verdict {
                    kind,
                    target: Some(target),
                    detail: None,
                    raw: format!("{tok} {}", tokens.get(i - 1).map(|s| s.as_str()).unwrap_or("")),
                };
            }
            "limit" | "log" | "counter" | "comment" | "synproxy" | "tproxy" | "dnat" | "snat"
            | "masquerade" | "redirect" | "mark" | "meter" | "numgen" | "jhash" | "symhash" => {
                i = skip_statement(&tokens, i, &tok, &mut b);
            }
            _ => {
                b.unsupported.push(format!("{tok}（按匹配所有处理）"));
                i += 1;
            }
        }
    }

    Ok(Rule {
        id: RuleId {
            table: table.to_string(),
            chain: chain.to_string(),
            index: 0,
        },
        file: file.to_string(),
        line_no,
        raw: line.to_string(),
        matches: b.ms,
        verdict,
        unsupported: b.unsupported,
    })
}

fn make_verdict(kind_tok: &str, tokens: &[String], i: &mut usize) -> Verdict {
    let kind = match kind_tok {
        "accept" => VerdictKind::Accept,
        "drop" => VerdictKind::Drop,
        "reject" => VerdictKind::Reject,
        "queue" => VerdictKind::Queue,
        "return" => VerdictKind::Return,
        _ => VerdictKind::Unknown,
    };
    let mut detail = None;
    // reject 可能带 with icmp ...
    while *i < tokens.len() {
        if tokens[*i] == "with" {
            let mut parts = Vec::new();
            *i += 1;
            while *i < tokens.len()
                && !matches!(tokens[*i].as_str(), "accept" | "drop" | "reject" | "jump" | "goto" | "return")
            {
                parts.push(tokens[*i].clone());
                *i += 1;
            }
            detail = Some(parts.join(" "));
        } else {
            break;
        }
    }
    Verdict {
        kind,
        target: None,
        detail,
        raw: kind_tok.to_string(),
    }
}

/// 跳过不参与判定的整条 statement（尽量跨过其参数，直到下一个已知关键字）。
fn skip_statement(tokens: &[String], i: usize, head: &str, b: &mut NftBuilder) -> usize {
    let known = [
        "ip", "ip6", "meta", "tcp", "udp", "udplite", "sctp", "th", "icmp", "icmpv6",
        "iifname", "oifname", "ct", "accept", "drop", "reject", "queue", "return",
        "jump", "goto",
    ];
    let mut j = i + 1;
    while j < tokens.len() && !known.contains(&tokens[j].as_str()) {
        j += 1;
    }
    b.unsupported
        .push(format!("{head} statement（按匹配所有处理）"));
    j
}
