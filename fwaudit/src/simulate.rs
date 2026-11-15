//! Packet simulation: walk a 5-tuple through chains, jumps and RETURNs.

use crate::model::{Ruleset, Target};
use crate::rect::{Family, NDIMS};

#[derive(Clone, Debug)]
pub struct Packet {
    pub family: Family,
    pub src: u128,
    pub dst: u128,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub iif: Option<String>,
    pub oif: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Event {
    EnterChain { chain: String, via: String },
    Match {
        chain: String,
        rule_index: usize,
        text: String,
        action: String,
        /// opaque predicates we had to assume true
        assumed: Vec<String>,
    },
    ChainEnd { chain: String },
    Return { from: String, to: Option<String> },
    Policy { chain: String, policy: String },
    Verdict { target: String },
    LoopDetected { note: String },
}

pub struct Trace {
    pub events: Vec<Event>,
    pub verdict: Option<String>,
}

fn rule_matches(rule: &crate::model::Rule, pkt: &Packet) -> Option<Vec<String>> {
    let pt: [u128; NDIMS] = [
        pkt.src,
        pkt.dst,
        pkt.proto as u128,
        pkt.sport as u128,
        pkt.dport as u128,
    ];
    for r in &rule.mset {
        if r.family != pkt.family {
            continue;
        }
        if let Some(i) = &r.iif {
            if pkt.iif.as_deref() != Some(i.as_str()) {
                continue;
            }
        }
        if let Some(o) = &r.oif {
            if pkt.oif.as_deref() != Some(o.as_str()) {
                continue;
            }
        }
        if r.contains_point(&pt) {
            return Some(r.atoms.iter().cloned().collect());
        }
    }
    None
}

pub fn simulate(rs: &Ruleset, table: &str, start_chain: &str, pkt: &Packet) -> Trace {
    let mut events = Vec::new();
    let mut verdict: Option<String> = None;
    // call stack: (chain name, next rule position) to resume after RETURN
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut cur_chain = start_chain.to_string();
    let mut pos = 0usize;
    let mut steps = 0usize;
    const MAX_STEPS: usize = 100_000;
    const MAX_DEPTH: usize = 64;

    events.push(Event::EnterChain {
        chain: cur_chain.clone(),
        via: "start".into(),
    });

    'outer: loop {
        steps += 1;
        if steps > MAX_STEPS {
            events.push(Event::LoopDetected {
                note: format!("exceeded {MAX_STEPS} rule evaluations (jump/goto loop?)"),
            });
            break;
        }
        let Some(chain) = rs.chain(table, &cur_chain) else {
            events.push(Event::LoopDetected {
                note: format!("chain '{}' not found in table '{}'", cur_chain, table),
            });
            break;
        };
        let mut matched = false;
        while pos < chain.rules.len() {
            let ridx = chain.rules[pos];
            let rule = &rs.rules[ridx];
            pos += 1;
            let Some(assumed) = rule_matches(rule, pkt) else {
                continue;
            };
            matched = true;
            let action = rule.target.describe();
            events.push(Event::Match {
                chain: cur_chain.clone(),
                rule_index: rule.index,
                text: rule.text.clone(),
                action: action.clone(),
                assumed,
            });
            match &rule.target {
                Target::Terminal(t) => {
                    verdict = Some(t.clone());
                    events.push(Event::Verdict { target: t.clone() });
                    break 'outer;
                }
                Target::NonTerminal(_) => {
                    continue; // keep walking the same chain
                }
                Target::Jump(c) => {
                    if stack.len() >= MAX_DEPTH {
                        events.push(Event::LoopDetected {
                            note: "jump depth exceeded".into(),
                        });
                        break 'outer;
                    }
                    stack.push((cur_chain.clone(), pos));
                    events.push(Event::EnterChain {
                        chain: c.clone(),
                        via: format!("jump from {} rule #{}", cur_chain, rule.index),
                    });
                    cur_chain = c.clone();
                    pos = 0;
                    continue 'outer;
                }
                Target::Goto(c) => {
                    events.push(Event::EnterChain {
                        chain: c.clone(),
                        via: format!("goto from {} rule #{}", cur_chain, rule.index),
                    });
                    cur_chain = c.clone();
                    pos = 0;
                    continue 'outer;
                }
                Target::Return => {
                    let from = cur_chain.clone();
                    match stack.pop() {
                        Some((c, p)) => {
                            events.push(Event::Return {
                                from,
                                to: Some(c.clone()),
                            });
                            events.push(Event::EnterChain {
                                chain: c.clone(),
                                via: "returned".into(),
                            });
                            cur_chain = c;
                            pos = p;
                            continue 'outer;
                        }
                        None => {
                            events.push(Event::Return { from, to: None });
                            // RETURN at top level: use chain policy if builtin
                            if let Some(pol) = &chain.policy {
                                events.push(Event::Policy {
                                    chain: cur_chain.clone(),
                                    policy: pol.clone(),
                                });
                                verdict = Some(pol.clone());
                            }
                            break 'outer;
                        }
                    }
                }
            }
        }
        // fell off the end of the chain
        events.push(Event::ChainEnd {
            chain: cur_chain.clone(),
        });
        let _ = matched;
        let chain = rs.chain(table, &cur_chain).unwrap();
        if chain.builtin {
            let pol = chain.policy.clone().unwrap_or_else(|| "ACCEPT".into());
            events.push(Event::Policy {
                chain: cur_chain.clone(),
                policy: pol.clone(),
            });
            verdict = Some(pol);
            break;
        }
        // user chain: implicit RETURN
        let from = cur_chain.clone();
        match stack.pop() {
            Some((c, p)) => {
                events.push(Event::Return {
                    from,
                    to: Some(c.clone()),
                });
                events.push(Event::EnterChain {
                    chain: c.clone(),
                    via: "returned".into(),
                });
                cur_chain = c;
                pos = p;
            }
            None => {
                events.push(Event::Return { from, to: None });
                break;
            }
        }
    }

    Trace { events, verdict }
}
