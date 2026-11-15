//! iptables-save 导出解析器。
//!
//! 支持格式：
//!   *filter
//!   :INPUT DROP [0:0]
//!   -A INPUT -s 10.0.0.0/8 -i eth+ -p tcp --dport 22 -j ACCEPT
//!
//! 同一字段重复出现按“交集”处理（与内核多 match 的 AND 语义一致，
//! 也使矛盾条件能被识别为空匹配）。

use crate::intervals::IntervalSet;
use crate::ip::{Family, IpNet};
use crate::model::*;
use std::collections::HashMap;

/// shell 风格切词：识别引号与反斜杠，`!` 单独成词。
pub fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' => {
                i += 1;
            }
            '!' => {
                out.push("!".to_string());
                i += 1;
            }
            '"' | '\'' => {
                let quote = chars[i];
                i += 1;
                let mut buf = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        buf.push(chars[i]);
                    } else {
                        buf.push(chars[i]);
                    }
                    i += 1;
                }
                i += 1; // 跳过收尾引号
                out.push(buf);
            }
            '\\' if i + 1 < chars.len() => {
                i += 1;
                out.push(chars[i].to_string());
                i += 1;
            }
            _ => {
                let mut buf = String::new();
                while i < chars.len() && !matches!(chars[i], ' ' | '\t') {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        buf.push(chars[i]);
                    } else {
                        buf.push(chars[i]);
                    }
                    i += 1;
                }
                out.push(buf);
            }
        }
    }
    out
}

/// 规则匹配构造器：从全集出发，逐条件做交集。
struct MatchBuilder {
    ms: MatchSet,
}

impl MatchBuilder {
    fn new(family: Family) -> Self {
        MatchBuilder {
            ms: MatchSet::universe(family),
        }
    }

    fn apply_ip(&mut self, field: &str, nets: &[IpNet], negated: bool) -> Result<(), String> {
        let fam = self.ms.family;
        let mut s = IntervalSet::new();
        for n in nets {
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
            "src" => self.ms.src_ip = self.ms.src_ip.intersect(&s),
            "dst" => self.ms.dst_ip = self.ms.dst_ip.intersect(&s),
            _ => unreachable!(),
        }
        Ok(())
    }

    fn apply_ip_range(&mut self, field: &str, spec: &str, negated: bool) -> Result<(), String> {
        let fam = self.ms.family;
        let (a, b) = spec
            .split_once('-')
            .ok_or_else(|| format!("非法 iprange: {spec}"))?;
        let lo = crate::ip::IpAddr::parse(a.trim())?;
        let hi = crate::ip::IpAddr::parse(b.trim())?;
        if lo.family != fam || hi.family != fam || lo.value > hi.value {
            return Err(format!("非法 iprange 区间: {spec}"));
        }
        let mut s = IntervalSet::range(lo.value, hi.value);
        if negated {
            s = IntervalSet::universe(fam.max_value()).subtract(&s);
        }
        match field {
            "src" => self.ms.src_ip = self.ms.src_ip.intersect(&s),
            "dst" => self.ms.dst_ip = self.ms.dst_ip.intersect(&s),
            _ => unreachable!(),
        }
        Ok(())
    }

    fn apply_proto(&mut self, proto: u8, negated: bool) {
        let mut s = IntervalSet::point(proto as u128);
        if negated {
            s = IntervalSet::universe(255).subtract(&s);
        }
        self.ms.proto = self.ms.proto.intersect(&s);
    }

    fn apply_ports(&mut self, field: &str, spec: &str, negated: bool) -> Result<(), String> {
        let fam = self.ms.family;
        let mut s = parse_port_spec(spec)?;
        if negated {
            s = IntervalSet::universe(65535).subtract(&s);
        }
        match field {
            "sport" => self.ms.src_port = self.ms.src_port.intersect(&s),
            "dport" => self.ms.dst_port = self.ms.dst_port.intersect(&s),
            _ => unreachable!(),
        }
        let _ = fam;
        Ok(())
    }

    fn apply_port_list(&mut self, field: &str, spec: &str, negated: bool) -> Result<(), String> {
        let fam = self.ms.family;
        let mut s = IntervalSet::new();
        for part in spec.split(',') {
            s = s.union(&parse_port_spec(part.trim())?);
        }
        if negated {
            s = IntervalSet::universe(65535).subtract(&s);
        }
        match field {
            "sport" => self.ms.src_port = self.ms.src_port.intersect(&s),
            "dport" => self.ms.dst_port = self.ms.dst_port.intersect(&s),
            _ => unreachable!(),
        }
        let _ = fam;
        Ok(())
    }

    fn apply_icmp_type(&mut self, spec: &str, negated: bool) -> Result<(), String> {
        let s0 = parse_icmp_spec(spec)?;
        let s = if negated {
            IntervalSet::universe(255).subtract(&s0)
        } else {
            s0
        };
        self.ms.icmp_type = self.ms.icmp_type.intersect(&s);
        Ok(())
    }

    fn apply_states(&mut self, spec: &str, negated: bool) -> Result<(), String> {
        let mut s = IntervalSet::new();
        for part in spec.split(',') {
            let name = part.trim().to_ascii_uppercase();
            match parse_conn_state(&name) {
                Some(st) => s = s.union(&IntervalSet::point(st as u128)),
                None => return Err(format!("未知 conntrack 状态: {part}")),
            }
        }
        if negated {
            s = IntervalSet::universe(4).subtract(&s);
        }
        self.ms.state = self.ms.state.intersect(&s);
        Ok(())
    }

    fn apply_iface(&mut self, field: &str, pat: &str, negated: bool) {
        let p = IfacePred::from_pat(pat.to_string(), negated);
        match field {
            "iif" => self.ms.iif = self.ms.iif.intersect(&p),
            "oif" => self.ms.oif = self.ms.oif.intersect(&p),
            _ => unreachable!(),
        }
    }
}

/// 端口/端口段：`80`、`80:88`、`:1024`、`1024:`。
fn parse_port_spec(spec: &str) -> Result<IntervalSet, String> {
    if let Some((a, b)) = spec.split_once(':') {
        let lo: u128 = if a.is_empty() {
            0
        } else {
            a.parse().map_err(|_| format!("非法端口: {a}"))?
        };
        let hi: u128 = if b.is_empty() {
            65535
        } else {
            b.parse().map_err(|_| format!("非法端口: {b}"))?
        };
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

fn parse_icmp_spec(spec: &str) -> Result<IntervalSet, String> {
    // 支持 "8"（echo-request）、"8/0"（type/code，按 type 建模）、"echo-request"
    let type_part = spec.split('/').next().unwrap_or(spec);
    if let Ok(t) = type_part.parse::<u128>() {
        if t > 255 {
            return Err(format!("ICMP 类型超出范围: {spec}"));
        }
        Ok(IntervalSet::point(t))
    } else {
        let name = type_part.to_ascii_lowercase();
        let known: HashMap<&str, u8> = [
            ("echo-reply", 0),
            ("destination-unreachable", 3),
            ("echo-request", 8),
            ("time-exceeded", 11),
        ]
        .into_iter()
        .collect();
        match known.get(name.as_str()) {
            Some(t) => Ok(IntervalSet::point(*t as u128)),
            None => Err(format!("未知 ICMP 类型名: {type_part}")),
        }
    }
}

fn proto_number(name: &str) -> Option<u8> {
    let p = match name.to_ascii_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "sctp" => 132,
        "all" => return None, // -p all 等于不约束
        other => other.parse::<u8>().ok()?,
    };
    Some(p)
}

pub fn parse_iptables_save(input: &str, file: &str, ruleset: &mut Ruleset) -> Result<(), String> {
    let mut current_table: Option<String> = None;
    // 表名 -> 协议族（iptables-save 单文件通常只有 IPv4；ip6tables-save 为 v6）
    let mut table_family: HashMap<String, Family> = HashMap::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(tname) = line.strip_prefix('*') {
            let tname = tname.trim().to_string();
            current_table = Some(tname.clone());
            let family = if tname == "security" || tname == "raw" || tname == "mangle" {
                // 这些表两族都可能；默认 v4，遇到 v6 地址再纠正
                Family::V4
            } else {
                Family::V4
            };
            table_family.entry(tname.clone()).or_insert(family);
            if ruleset.table_mut(&tname).is_none() {
                ruleset.tables.push(Table {
                    name: tname.clone(),
                    family,
                    chains: Vec::new(),
                });
            }
            continue;
        }

        if line.starts_with(':') {
            let table_name = current_table
                .clone()
                .ok_or_else(|| format!("第 {line_no} 行: 链声明出现在表声明之前"))?;
            // :INPUT DROP [0:0]
            let body = &line[1..];
            let tokens = tokenize(body);
            if tokens.is_empty() {
                return Err(format!("第 {line_no} 行: 非法链声明 {line}"));
            }
            let chain_name = tokens[0].clone();
            let policy = if tokens.len() > 1 && tokens[1] != "-" {
                Some(tokens[1].clone())
            } else {
                None
            };
            let counters = tokens
                .iter()
                .find(|t| t.starts_with('['))
                .and_then(|t| t.trim_start_matches('[').strip_suffix(']'))
                .and_then(|s| s.split_once(':'))
                .map(|(p, b)| (p.parse::<u64>().unwrap_or(0), b.parse::<u64>().unwrap_or(0)))
                .unwrap_or((0, 0));
            let table = ruleset
                .table_mut(&table_name)
                .expect("表已创建");
            if table.chain_mut(&chain_name).is_none() {
                table.chains.push(Chain {
                    name: chain_name,
                    policy,
                    counters,
                    hook: None,
                    rules: Vec::new(),
                });
            }
            continue;
        }

        if line.starts_with("-A") || line.starts_with("--append") {
            let table_name = current_table
                .clone()
                .ok_or_else(|| format!("第 {line_no} 行: 规则出现在表声明之前"))?;
            let family = *table_family.get(&table_name).unwrap_or(&Family::V4);
            let rule = parse_rule(line, file, line_no, &table_name, family)?;
            // 规则里若出现 v6 地址，纠正表族
            let chain_name = rule.id.chain.clone();
            let needs_chain = {
                let table = ruleset.table(&table_name).expect("表已创建");
                if rule.matches.family == Family::V6 {
                    // 表族纠正放在可变借用内
                }
                table.chain(&chain_name).is_none()
            };
            if needs_chain {
                ruleset.warnings.push(format!(
                    "{file}:{line_no}: 链 {chain_name} 未声明，按自定义链处理"
                ));
            }
            let table = ruleset
                .table_mut(&table_name)
                .expect("表已创建");
            if rule.matches.family == Family::V6 {
                table.family = Family::V6;
            }
            if needs_chain {
                table.chains.push(Chain {
                    name: chain_name.clone(),
                    policy: None,
                    counters: (0, 0),
                    hook: None,
                    rules: Vec::new(),
                });
            }
            let chain = table.chain_mut(&chain_name).unwrap();
            let mut rule = rule;
            rule.id.index = chain.rules.len();
            chain.rules.push(rule);
            continue;
        }

        if line == "COMMIT" {
            continue;
        }

        ruleset.warnings.push(format!(
            "{file}:{line_no}: 忽略无法识别的行: {line}"
        ));
    }
    Ok(())
}

fn parse_rule(
    line: &str,
    file: &str,
    line_no: usize,
    table: &str,
    family: Family,
) -> Result<Rule, String> {
    let tokens = tokenize(line);
    let mut b = MatchBuilder::new(family);
    let mut unsupported = Vec::new();
    let mut verdict: Option<Verdict> = None;
    let mut i = 0;

    // 跳过 -A/--append 与链名
    i += 1;
    let chain_name = if i < tokens.len() && !tokens[i].starts_with('-') && tokens[i] != "!" {
        let name = tokens[i].clone();
        i += 1;
        name
    } else {
        return Err(format!("第 {line_no} 行: 缺少链名: {line}"));
    };

    let take_neg = |tokens: &[String], i: &mut usize| -> bool {
        if *i < tokens.len() && tokens[*i] == "!" {
            *i += 1;
            true
        } else {
            false
        }
    };

    while i < tokens.len() {
        // iptables 取反写法：`! -s 10/8`（! 在选项前），也兼容 `-s ! 10/8`
        let leading_neg = take_neg(&tokens, &mut i);
        let tok = &tokens[i];
        match tok.as_str() {
            "-s" | "--source" | "--src" => {
                i += 1;
                let mut neg = take_neg(&tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(&tokens, &mut i, line_no)?;
                let nets = parse_nets(&val)?;
                b.apply_ip("src", &nets, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "-d" | "--destination" | "--dst" => {
                i += 1;
                let mut neg = take_neg(&tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(&tokens, &mut i, line_no)?;
                let nets = parse_nets(&val)?;
                b.apply_ip("dst", &nets, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "-p" | "--protocol" => {
                i += 1;
                let mut neg = take_neg(&tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(&tokens, &mut i, line_no)?;
                match proto_number(&val) {
                    Some(num) => b.apply_proto(num, neg),
                    None if val.eq_ignore_ascii_case("all") => {
                        if neg {
                            return Err(format!(
                                "第 {line_no} 行: '! -p all' 语义为空，无法建模"
                            ));
                        }
                    }
                    None => {
                        return Err(format!("第 {line_no} 行: 未知协议 {val}"));
                    }
                }
            }
            "-i" | "--in-interface" => {
                i += 1;
                let mut neg = take_neg(&tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(&tokens, &mut i, line_no)?;
                b.apply_iface("iif", &val, neg);
            }
            "-o" | "--out-interface" => {
                i += 1;
                let mut neg = take_neg(&tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(&tokens, &mut i, line_no)?;
                b.apply_iface("oif", &val, neg);
            }
            "-m" | "--match" => {
                i += 1;
                let module = next_val(&tokens, &mut i, line_no)?;
                i = parse_module(&tokens, i, &module, &mut b, &mut unsupported, line_no)?;
            }
            "-j" | "--jump" => {
                i += 1;
                let val = next_val(&tokens, &mut i, line_no)?;
                verdict = Some(build_verdict(&val, &tokens, &mut i));
            }
            "-g" | "--goto" => {
                i += 1;
                let val = next_val(&tokens, &mut i, line_no)?;
                verdict = Some(Verdict {
                    kind: VerdictKind::Goto,
                    raw: format!("goto {val}"),
                    target: Some(val),
                    detail: None,
                });
            }
            "--counters" => {
                i += 1;
                let _ = next_val(&tokens, &mut i, line_no)?;
                let _ = next_val(&tokens, &mut i, line_no)?;
            }
            // 不带 -m 的隐式模块长选项
            "--icmp-type" => {
                i += 1;
                let neg = take_neg(&tokens, &mut i);
                let val = next_val(&tokens, &mut i, line_no)?;
                b.apply_icmp_type(&val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--ctstate" | "--state" => {
                i += 1;
                let neg = take_neg(&tokens, &mut i);
                let val = next_val(&tokens, &mut i, line_no)?;
                b.apply_states(&val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            other if other.starts_with('-') => {
                // 未带 -m 的直接长选项，尽力处理；前置 `!` 透传进去
                i += 1;
                if let Some(rest) = handle_loose_option(
                    other,
                    leading_neg,
                    &tokens,
                    &mut i,
                    &mut b,
                    line_no,
                )? {
                    unsupported.push(rest);
                }
            }
            _ => {
                unsupported.push(tok.clone());
                i += 1;
            }
        }
    }

    let verdict = verdict.unwrap_or(Verdict {
        kind: VerdictKind::Unknown,
        target: None,
        detail: None,
        raw: "<无动作>".to_string(),
    });

    Ok(Rule {
        id: RuleId {
            table: table.to_string(),
            chain: chain_name,
            index: 0,
        },
        file: file.to_string(),
        line_no,
        raw: line.to_string(),
        matches: b.ms,
        verdict,
        unsupported,
    })
}

fn next_val(tokens: &[String], i: &mut usize, line_no: usize) -> Result<String, String> {
    if *i >= tokens.len() {
        return Err(format!("第 {line_no} 行: 选项缺少参数"));
    }
    let v = tokens[*i].clone();
    *i += 1;
    Ok(v)
}

fn parse_nets(val: &str) -> Result<Vec<IpNet>, String> {
    val.split(',')
        .map(|s| IpNet::parse(s.trim()))
        .collect()
}

/// 处理 `-m <module>` 之后属于该模块的选项，直到遇到下一个顶层选项无法识别为止。
/// 返回消耗 token 后的新下标。
fn parse_module(
    tokens: &[String],
    mut i: usize,
    module: &str,
    b: &mut MatchBuilder,
    unsupported: &mut Vec<String>,
    line_no: usize,
) -> Result<usize, String> {
    let take_neg = |tokens: &[String], i: &mut usize| -> bool {
        if *i < tokens.len() && tokens[*i] == "!" {
            *i += 1;
            true
        } else {
            false
        }
    };

    while i < tokens.len() {
        // 模块内取反也可能写在选项前：`! --dport 22`
        let leading_neg = take_neg(tokens, &mut i);
        let opt = tokens[i].clone();
        match opt.as_str() {
            "--sport" | "--source-port" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_ports("sport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--dport" | "--destination-port" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                // multiport 的 --dports 也会走到这里，带逗号时按列表解析
                if val.contains(',') {
                    b.apply_port_list("dport", &val, neg)
                        .map_err(|e| format!("第 {line_no} 行: {e}"))?;
                } else {
                    b.apply_ports("dport", &val, neg)
                        .map_err(|e| format!("第 {line_no} 行: {e}"))?;
                }
            }
            "--sports" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_port_list("sport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--dports" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_port_list("dport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--ports" => {
                // multiport --ports：同时约束源或目的，保守取目的端口语义并标注
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_port_list("dport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--source-ports" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_port_list("sport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--destination-ports" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_port_list("dport", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--src-range" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_ip_range("src", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--dst-range" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_ip_range("dst", &val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--icmp-type" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_icmp_type(&val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--ctstate" | "--state" => {
                i += 1;
                let mut neg = take_neg(tokens, &mut i);
                neg ^= leading_neg;
                let val = next_val(tokens, &mut i, line_no)?;
                b.apply_states(&val, neg)
                    .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            }
            "--tcp-flags" => {
                // --tcp-flags MASK CMP：按不约束处理（精确建模需位运算），记录告警
                i += 1;
                let mask = next_val(tokens, &mut i, line_no)?;
                let cmp = next_val(tokens, &mut i, line_no)?;
                unsupported.push(format!("tcp-flags {mask} {cmp}（按匹配所有处理）"));
            }
            "--syn" => {
                i += 1;
                unsupported.push("tcp --syn（按匹配所有处理）".to_string());
            }
            "--ctdir" | "--ctorigsrc" | "--ctorigdst" | "--ctreplsrc" | "--ctrepldst"
            | "--ctexpire" | "--limit" | "--limit-burst" | "--mac-source"
            | "--comment" | "--log-prefix" | "--log-level" | "--reject-with"
            | "--queue-num" | "--set-mark" | "--set-xmark" | "--mark" | "--goto" => {
                // 纯修饰/不参与五元组判定的选项，跳过其参数（reject-with 在 verdict 里另处理）
                i += 1;
                skip_option_args(&opt, tokens, &mut i, line_no)?;
            }
            other if other.starts_with("--") => {
                // 未知模块选项：保守按匹配所有，记录
                i += 1;
                if i < tokens.len() && !tokens[i].starts_with('-') && tokens[i] != "!" {
                    let arg = tokens[i].clone();
                    i += 1;
                    unsupported.push(format!("{module} {other} {arg}（按匹配所有处理）"));
                } else {
                    unsupported.push(format!("{module} {other}（按匹配所有处理）"));
                }
            }
            _ => break,
        }
    }
    Ok(i)
}

fn skip_option_args(
    opt: &str,
    tokens: &[String],
    i: &mut usize,
    line_no: usize,
) -> Result<(), String> {
    // --comment 的参数可能含空格但已被 tokenize 合并；统一吃一个非选项参数。
    let needs_arg = matches!(
        opt,
        "--ctdir"
            | "--ctorigsrc"
            | "--ctorigdst"
            | "--ctreplsrc"
            | "--ctrepldst"
            | "--ctexpire"
            | "--limit"
            | "--limit-burst"
            | "--mac-source"
            | "--comment"
            | "--log-prefix"
            | "--log-level"
            | "--reject-with"
            | "--queue-num"
            | "--set-mark"
            | "--set-xmark"
            | "--mark"
    );
    if needs_arg && *i < tokens.len() && !tokens[*i].starts_with('-') {
        let _ = next_val(tokens, i, line_no)?;
    }
    Ok(())
}

fn handle_loose_option(
    opt: &str,
    leading_neg: bool,
    tokens: &[String],
    i: &mut usize,
    b: &mut MatchBuilder,
    line_no: usize,
) -> Result<Option<String>, String> {
    // 不带 -m 直接出现的 --dport 等（iptables 允许隐式模块）
    match opt {
        "--dport" | "--destination-port" => {
            let trailing = *i < tokens.len() && tokens[*i] == "!";
            if trailing {
                *i += 1;
            }
            let neg = leading_neg ^ trailing;
            let val = next_val(tokens, i, line_no)?;
            b.apply_ports("dport", &val, neg)
                .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            Ok(None)
        }
        "--sport" | "--source-port" => {
            let trailing = *i < tokens.len() && tokens[*i] == "!";
            if trailing {
                *i += 1;
            }
            let neg = leading_neg ^ trailing;
            let val = next_val(tokens, i, line_no)?;
            b.apply_ports("sport", &val, neg)
                .map_err(|e| format!("第 {line_no} 行: {e}"))?;
            Ok(None)
        }
        _ => {
            if *i < tokens.len() && !tokens[*i].starts_with('-') {
                let arg = tokens[*i].clone();
                *i += 1;
                Ok(Some(format!("{opt} {arg}")))
            } else {
                Ok(Some(opt.to_string()))
            }
        }
    }
}

fn build_verdict(target: &str, tokens: &[String], i: &mut usize) -> Verdict {
    let kind = match target.to_ascii_uppercase().as_str() {
        "ACCEPT" => VerdictKind::Accept,
        "DROP" => VerdictKind::Drop,
        "REJECT" => VerdictKind::Reject,
        "QUEUE" => VerdictKind::Queue,
        "RETURN" => VerdictKind::Return,
        _ => VerdictKind::Jump,
    };
    let mut detail = None;
    // 吞掉 --reject-with 等后续参数
    while *i < tokens.len() {
        if tokens[*i] == "--reject-with" {
            *i += 1;
            if *i < tokens.len() {
                detail = Some(tokens[*i].clone());
                *i += 1;
            }
        } else if tokens[*i].starts_with("--") {
            *i += 1;
            if *i < tokens.len() && !tokens[*i].starts_with('-') {
                *i += 1;
            }
        } else {
            break;
        }
    }
    let jump_target = if kind == VerdictKind::Jump {
        Some(target.to_string())
    } else {
        None
    };
    Verdict {
        kind,
        target: jump_target,
        detail,
        raw: target.to_string(),
    }
}
