//! 报文路径模拟：给定五元组（及可选接口/状态/ICMP 类型），
//! 精确复现 netfilter 的链遍历，打印每一跳与命中的规则。

use crate::ip::IpAddr;
use crate::model::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Packet {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub iif: String,
    pub oif: String,
    pub icmp_type: Option<u8>,
    pub state: Option<ConnState>,
}

#[derive(Debug, Clone)]
pub struct TraceStep {
    pub table: String,
    pub chain: String,
    /// 链内被求值过的规则序号（含未命中）。
    pub evaluated: Vec<usize>,
    /// 命中的规则序号与动作。
    pub hit: Option<(usize, String)>,
    /// 离开本链的原因。
    pub outcome: String,
}

#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// 最终判定（ACCEPT/DROP/REJECT/QUEUE/默认策略/RETURN 回退）。
    pub final_verdict: String,
    pub steps: Vec<TraceStep>,
    pub loop_detected: bool,
    pub error: Option<String>,
}

fn packet_in_set(v: u128, set: &crate::intervals::IntervalSet) -> bool {
    set.contains(v)
}

fn rule_matches(rule: &Rule, pkt: &Packet) -> bool {
    let m = &rule.matches;
    if m.family != pkt.src_ip.family || pkt.src_ip.family != pkt.dst_ip.family {
        return false;
    }
    if !packet_in_set(pkt.src_ip.value, &m.src_ip) {
        return false;
    }
    if !packet_in_set(pkt.dst_ip.value, &m.dst_ip) {
        return false;
    }
    if !packet_in_set(pkt.proto as u128, &m.proto) {
        return false;
    }
    if !packet_in_set(pkt.src_port as u128, &m.src_port) {
        return false;
    }
    if !packet_in_set(pkt.dst_port as u128, &m.dst_port) {
        return false;
    }
    // 可选维度：只有规则约束了该维度时才要求报文提供值。
    // 规则未约束（等于全集）则放行；规则有约束而报文缺该维度，则不匹配。
    let uni = MatchSet::universe(pkt.src_ip.family);
    if m.icmp_type != uni.icmp_type {
        match pkt.icmp_type {
            Some(t) => {
                if !packet_in_set(t as u128, &m.icmp_type) {
                    return false;
                }
            }
            None => return false,
        }
    }
    if m.state != uni.state {
        match pkt.state {
            Some(s) => {
                if !packet_in_set(s as u128, &m.state) {
                    return false;
                }
            }
            None => return false,
        }
    }
    // 接口：规则约束为非通配时，报文接口名必须满足；报文给空名且规则要求具体接口则不匹配。
    if m.iif != uni.iif && !m.iif.matches_name(&pkt.iif) {
        return false;
    }
    if m.oif != uni.oif && !m.oif.matches_name(&pkt.oif) {
        return false;
    }
    true
}

/// 模拟入口。`start_table`/`start_chain` 指定入口（通常是基础链）。
pub fn simulate(
    ruleset: &Ruleset,
    pkt: &Packet,
    start_table: &str,
    start_chain: &str,
) -> SimulationResult {
    let mut steps = Vec::new();
    // 调用栈：(表, 链, 是否 goto)。goto 链返回时不回到调用者。
    let mut stack: Vec<(String, String, bool)> = vec![(
        start_table.to_string(),
        start_chain.to_string(),
        false,
    )];
    // (表, 链, 规则序号游标) —— 用于 RETURN 后回到调用链下一条规则
    let mut cursor_stack: Vec<usize> = vec![0];
    let mut visit_count: HashMap<(String, String), u32> = HashMap::new();
    let mut loop_detected = false;
    let mut error = None;
    let mut final_verdict = String::new();

    'outer: while let Some((tname, cname, is_goto)) = stack.last().cloned() {
        let key = (tname.clone(), cname.clone());
        let count = visit_count.entry(key.clone()).or_insert(0);
        *count += 1;
        if *count > 64 {
            loop_detected = true;
            error = Some(format!("检测到链跳转环（{tname}:{cname} 重复进入），停止模拟"));
            break;
        }

        let Some(table) = ruleset.table(&tname) else {
            error = Some(format!("表 {tname} 不存在"));
            break;
        };
        let Some(chain) = table.chain(&cname) else {
            error = Some(format!("链 {tname}:{cname} 不存在"));
            break;
        };

        let start_idx = *cursor_stack.last().unwrap();
        let mut evaluated = Vec::new();
        let mut hit: Option<(usize, String)> = None;
        let outcome;

        let mut idx = start_idx;
        loop {
            if idx >= chain.rules.len() {
                // 走到链尾
                if let Some(policy) = &chain.policy {
                    outcome = format!("链尾，应用默认策略 {policy}");
                    final_verdict = policy.clone();
                } else {
                    outcome = "链尾，RETURN 回退到调用链".to_string();
                    final_verdict = "RETURN".to_string();
                }
                break;
            }

            let rule = &chain.rules[idx];
            evaluated.push(idx);
            if rule_matches(rule, pkt) {
                hit = Some((idx, rule.verdict.raw.clone()));
                match rule.verdict.kind {
                    VerdictKind::Accept
                    | VerdictKind::Drop
                    | VerdictKind::Reject
                    | VerdictKind::Queue => {
                        outcome = format!("命中规则 #{idx}，判定 {}", rule.verdict.raw);
                        final_verdict = rule.verdict.raw.to_ascii_uppercase();
                        steps.push(TraceStep {
                            table: tname.clone(),
                            chain: cname.clone(),
                            evaluated,
                            hit,
                            outcome,
                        });
                        break 'outer;
                    }
                    VerdictKind::Return => {
                        outcome = format!("命中规则 #{idx}，RETURN");
                        steps.push(TraceStep {
                            table: tname.clone(),
                            chain: cname.clone(),
                            evaluated: evaluated.clone(),
                            hit: hit.clone(),
                            outcome: outcome.clone(),
                        });
                        break;
                    }
                    VerdictKind::Jump | VerdictKind::Goto => {
                        let target = rule.verdict.target.clone().unwrap_or_default();
                        let goto = rule.verdict.kind == VerdictKind::Goto;
                        outcome = format!(
                            "命中规则 #{idx}，{} -> {target}",
                            if goto { "GOTO" } else { "JUMP" }
                        );
                        steps.push(TraceStep {
                            table: tname.clone(),
                            chain: cname.clone(),
                            evaluated: evaluated.clone(),
                            hit: hit.clone(),
                            outcome: outcome.clone(),
                        });
                        // 调用链的游标推进到下一条
                        *cursor_stack.last_mut().unwrap() = idx + 1;
                        if goto {
                            // Goto：替换栈顶，永不返回本链
                            stack.pop();
                            cursor_stack.pop();
                        }
                        if ruleset
                            .table(&tname)
                            .and_then(|t| t.chain(&target))
                            .is_none()
                        {
                            error = Some(format!(
                                "规则 #{idx} 跳转到不存在的链 {target}，停止模拟"
                            ));
                            final_verdict = "ERROR".to_string();
                            break 'outer;
                        }
                        stack.push((tname.clone(), target, goto));
                        cursor_stack.push(0);
                        continue 'outer;
                    }
                    VerdictKind::Unknown => {
                        // 未知动作不终结，继续向下求值；outcome 由后续命中或链尾决定。
                    }
                }
            }
            idx += 1;
        }

        steps.push(TraceStep {
            table: tname.clone(),
            chain: cname.clone(),
            evaluated,
            hit,
            outcome: outcome.clone(),
        });

        // 离开本链
        stack.pop();
        cursor_stack.pop();
        if stack.is_empty() {
            if final_verdict.is_empty() {
                final_verdict = chain
                    .policy
                    .clone()
                    .unwrap_or_else(|| "RETURN".to_string());
            }
            break;
        }
        // 非 goto 的正常返回：调用链从游标处继续（游标已在跳转前推进）
        let _ = is_goto;
    }

    if final_verdict.is_empty() && error.is_none() {
        final_verdict = "UNKNOWN".to_string();
    }

    SimulationResult {
        final_verdict,
        steps,
        loop_detected,
        error,
    }
}
