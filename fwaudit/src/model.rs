//! Data model shared by parsers, analysis and simulation.

use crate::rect::MatchSet;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Backend {
    Iptables,
    Nftables,
}

impl Default for Backend {
    fn default() -> Self {
        Backend::Iptables
    }
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Iptables => "iptables",
            Backend::Nftables => "nftables",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Verdict that ends traversal of the current chain (ACCEPT, DROP, ...).
    Terminal(String),
    /// Non-terminating extension target (LOG, MARK, ...).
    NonTerminal(String),
    Jump(String),
    Goto(String),
    Return,
}

impl Target {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Target::Terminal(_))
    }
    pub fn describe(&self) -> String {
        match self {
            Target::Terminal(t) => t.clone(),
            Target::NonTerminal(t) => format!("{t} (non-terminal)"),
            Target::Jump(c) => format!("jump -> {c}"),
            Target::Goto(c) => format!("goto -> {c}"),
            Target::Return => "RETURN".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub table: String,
    pub chain: String,
    /// 1-based position inside its chain (matches iptables --line-numbers).
    pub index: usize,
    pub text: String,
    pub mset: MatchSet,
    pub target: Target,
    /// Source file, for diagnostics.
    pub origin: String,
}

#[derive(Clone, Debug)]
pub struct Chain {
    pub table: String,
    pub name: String,
    pub builtin: bool,
    pub policy: Option<String>,
    /// Indices into Ruleset::rules, in order.
    pub rules: Vec<usize>,
}

#[derive(Default)]
pub struct Ruleset {
    pub backend: Backend,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
    /// (table, chain) -> index into chains
    pub chain_idx: BTreeMap<(String, String), usize>,
    pub warnings: Vec<String>,
}

impl Ruleset {
    pub fn new(backend: Backend) -> Self {
        Ruleset {
            backend,
            ..Default::default()
        }
    }

    pub fn get_or_add_chain(&mut self, table: &str, name: &str) -> usize {
        if let Some(&i) = self.chain_idx.get(&(table.to_string(), name.to_string())) {
            return i;
        }
        let idx = self.chains.len();
        self.chains.push(Chain {
            table: table.to_string(),
            name: name.to_string(),
            builtin: false,
            policy: None,
            rules: Vec::new(),
        });
        self.chain_idx
            .insert((table.to_string(), name.to_string()), idx);
        idx
    }

    pub fn add_rule(&mut self, mut rule: Rule) {
        let cidx = self.get_or_add_chain(&rule.table.clone(), &rule.chain.clone());
        rule.index = self.chains[cidx].rules.len() + 1;
        let ridx = self.rules.len();
        self.chains[cidx].rules.push(ridx);
        self.rules.push(rule);
    }

    pub fn chain(&self, table: &str, name: &str) -> Option<&Chain> {
        self.chain_idx
            .get(&(table.to_string(), name.to_string()))
            .map(|&i| &self.chains[i])
    }

    pub fn warn(&mut self, msg: String) {
        self.warnings.push(msg);
    }

    /// Merge another ruleset (same backend). Chains with the same
    /// (table, name) are appended to.
    pub fn merge(&mut self, other: Ruleset) {
        let base = self.rules.len();
        let mut chain_remap: Vec<usize> = Vec::with_capacity(other.chains.len());
        for c in &other.chains {
            let idx = self.get_or_add_chain(&c.table, &c.name);
            let ch = &mut self.chains[idx];
            if c.builtin {
                ch.builtin = true;
            }
            if c.policy.is_some() {
                ch.policy = c.policy.clone();
            }
            chain_remap.push(idx);
        }
        for r in other.rules {
            self.rules.push(r);
        }
        // re-link chain membership and renumber
        for (old_cidx, c) in other.chains.iter().enumerate() {
            let new_cidx = chain_remap[old_cidx];
            for &old_ridx in &c.rules {
                let new_ridx = base + old_ridx;
                let idx_in_chain = self.chains[new_cidx].rules.len() + 1;
                self.chains[new_cidx].rules.push(new_ridx);
                self.rules[new_ridx].index = idx_in_chain;
            }
        }
        self.warnings.extend(other.warnings);
    }
}
