//! Parser for `nft list ruleset` output.
//!
//! Supports: table/chain/set blocks, chain policies, address/port matches
//! (single, set literal, @named-set, ranges, != negation), protocol matches,
//! interfaces, ct state (opaque), and the common verdicts. Anything not
//! understood is kept as an opaque predicate so analysis stays sound.

use crate::model::{Backend, Rule, Ruleset, Target};
use crate::parseutil::*;
use crate::rect::{Family, IntervalSet};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
enum T {
    Word(String),
    Str(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Semi,
    Comma,
    Newline,
}

fn tokenize(text: &str) -> Vec<T> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '\n' => {
                out.push(T::Newline);
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            '#' => {
                while let Some(&c) = chars.peek() {
                    if c == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '{' => {
                out.push(T::LBrace);
                chars.next();
            }
            '}' => {
                out.push(T::RBrace);
                chars.next();
            }
            '(' => {
                out.push(T::LParen);
                chars.next();
            }
            ')' => {
                out.push(T::RParen);
                chars.next();
            }
            ';' => {
                out.push(T::Semi);
                chars.next();
            }
            ',' => {
                out.push(T::Comma);
                chars.next();
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '"' {
                        chars.next();
                        break;
                    }
                    if c == '\\' {
                        chars.next();
                        if let Some(&e) = chars.peek() {
                            s.push(e);
                            chars.next();
                        }
                        continue;
                    }
                    s.push(c);
                    chars.next();
                }
                out.push(T::Str(s));
            }
            _ => {
                let mut w = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '{' | '}' | '(' | ')' | ';' | ',' | '#' | '"') {
                        break;
                    }
                    w.push(c);
                    chars.next();
                }
                out.push(T::Word(w));
            }
        }
    }
    out
}

#[derive(Clone)]
enum NamedSet {
    Addrs(Family, IntervalSet),
    Ports(IntervalSet),
    Ifaces(#[allow(dead_code)] Vec<String>),
    Other,
}

struct Parser<'a> {
    toks: &'a [T],
    pos: usize,
    rs: Ruleset,
    origin: String,
    /// (table, setname) -> set
    sets: HashMap<(String, String), NamedSet>,
}

struct PendingRule {
    table: String,
    chain: String,
    builder: RuleBuilder,
    text: String,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&T> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<&T> {
        let t = self.toks.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn word(&self) -> Option<&str> {
        match self.peek() {
            Some(T::Word(w)) => Some(w.as_str()),
            Some(T::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    fn take_word(&mut self) -> Option<String> {
        match self.peek() {
            Some(T::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Some(w)
            }
            Some(T::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => None,
        }
    }
    fn eat(&mut self, t: &T) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn skip_separators(&mut self) {
        while matches!(self.peek(), Some(T::Newline) | Some(T::Semi)) {
            self.pos += 1;
        }
    }
    /// Skip to next Newline/Semi/RBrace (does not consume the RBrace).
    fn skip_stmt(&mut self) {
        let mut depth = 0i32;
        while let Some(t) = self.peek() {
            match t {
                T::LBrace | T::LParen => depth += 1,
                T::RBrace | T::RParen => {
                    if depth == 0 {
                        return;
                    }
                    depth -= 1;
                }
                T::Newline | T::Semi if depth == 0 => {
                    self.pos += 1;
                    return;
                }
                _ => {}
            }
            self.pos += 1;
        }
    }
    fn skip_block(&mut self) {
        // positioned after the opening LBrace
        let mut depth = 1i32;
        while let Some(t) = self.next() {
            match t {
                T::LBrace => depth += 1,
                T::RBrace => {
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn parse(text: &str, origin: &str) -> Ruleset {
    let toks = tokenize(text);
    let mut p = Parser {
        toks: &toks,
        pos: 0,
        rs: Ruleset::new(Backend::Nftables),
        origin: origin.to_string(),
        sets: HashMap::new(),
    };
    let mut pending: Vec<PendingRule> = Vec::new();
    p.run(&mut pending);

    // resolve jump/goto targets now that every chain is known
    let chains: std::collections::BTreeSet<(String, String)> =
        p.rs.chain_idx.keys().cloned().collect();
    for pr in pending {
        let (raw, is_goto) = pr
            .builder
            .target
            .clone()
            .unwrap_or_else(|| ("LOG".into(), false));
        let target = resolve_target(&raw, is_goto, &pr.table, &chains, &mut p.rs);
        let mset = pr.builder.build();
        p.rs.add_rule(Rule {
            table: pr.table,
            chain: pr.chain,
            index: 0,
            text: pr.text,
            mset,
            target,
            origin: origin.to_string(),
        });
    }
    p.rs
}

fn resolve_target(
    raw: &str,
    is_goto: bool,
    table: &str,
    chains: &std::collections::BTreeSet<(String, String)>,
    rs: &mut Ruleset,
) -> Target {
    let low = raw.to_ascii_lowercase();
    match low.as_str() {
        "accept" => return Target::Terminal("ACCEPT".into()),
        "drop" => return Target::Terminal("DROP".into()),
        "reject" => return Target::Terminal("REJECT".into()),
        "return" => return Target::Return,
        "masquerade" => return Target::Terminal("MASQUERADE".into()),
        "snat" => return Target::Terminal("SNAT".into()),
        "dnat" => return Target::Terminal("DNAT".into()),
        "redirect" => return Target::Terminal("REDIRECT".into()),
        "notrack" => return Target::Terminal("NOTRACK".into()),
        "queue" => return Target::Terminal("QUEUE".into()),
        "log" => return Target::NonTerminal("LOG".into()),
        _ => {}
    }
    if chains.contains(&(table.to_string(), raw.to_string())) {
        return if is_goto {
            Target::Goto(raw.to_string())
        } else {
            Target::Jump(raw.to_string())
        };
    }
    rs.warn(format!("unknown nft verdict '{raw}', treated as non-terminal"));
    Target::NonTerminal(raw.to_string())
}

impl<'a> Parser<'a> {
    fn run(&mut self, pending: &mut Vec<PendingRule>) {
        loop {
            self.skip_separators();
            let Some(w) = self.word().map(|s| s.to_string()) else {
                if self.peek().is_some() {
                    self.pos += 1;
                    continue;
                }
                break;
            };
            match w.as_str() {
                "table" => {
                    self.pos += 1;
                    let family = self.take_word().unwrap_or_default();
                    let name = self.take_word().unwrap_or_default();
                    let table = format!("{family}/{name}");
                    if !self.eat(&T::LBrace) {
                        self.skip_stmt();
                        continue;
                    }
                    self.parse_table_body(&table, pending);
                }
                "include" | "#" => self.skip_stmt(),
                _ => self.skip_stmt(),
            }
        }
    }

    fn parse_table_body(&mut self, table: &str, pending: &mut Vec<PendingRule>) {
        // first pass inside the table: sets are collected, chain bodies are
        // parsed immediately (nft prints sets before the chains that use
        // them; if not, the @lookup degrades to an opaque predicate)
        loop {
            self.skip_separators();
            match self.peek() {
                None => return,
                Some(T::RBrace) => {
                    self.pos += 1;
                    return;
                }
                _ => {}
            }
            let Some(w) = self.word().map(|s| s.to_string()) else {
                self.pos += 1;
                continue;
            };
            match w.as_str() {
                "chain" => {
                    self.pos += 1;
                    let name = self.take_word().unwrap_or_default();
                    if !self.eat(&T::LBrace) {
                        self.skip_stmt();
                        continue;
                    }
                    self.parse_chain_body(table, &name, pending);
                }
                "set" => {
                    self.pos += 1;
                    let name = self.take_word().unwrap_or_default();
                    if !self.eat(&T::LBrace) {
                        self.skip_stmt();
                        continue;
                    }
                    self.parse_set_body(table, &name);
                }
                "map" | "flowtable" | "counter" | "quota" | "limit" | "ct" | "secmark"
                | "synproxy" => {
                    // named stateful objects: skip the whole block
                    self.pos += 1;
                    let _ = self.take_word();
                    if self.eat(&T::LBrace) {
                        self.skip_block();
                    } else {
                        self.skip_stmt();
                    }
                }
                _ => self.skip_stmt(),
            }
        }
    }

    fn parse_set_body(&mut self, table: &str, name: &str) {
        let mut ty = String::new();
        let mut elements: Vec<String> = Vec::new();
        loop {
            match self.peek() {
                None => return,
                Some(T::RBrace) => {
                    self.pos += 1;
                    break;
                }
                Some(T::Newline) | Some(T::Semi) | Some(T::Comma) => {
                    self.pos += 1;
                    continue;
                }
                _ => {}
            }
            let Some(w) = self.word().map(|s| s.to_string()) else {
                self.pos += 1;
                continue;
            };
            match w.as_str() {
                "type" => {
                    self.pos += 1;
                    // may be "ipv4_addr" or concatenated "a . b"
                    let mut parts = Vec::new();
                    while let Some(t) = self.peek() {
                        match t {
                            T::Word(x) => {
                                parts.push(x.clone());
                                self.pos += 1;
                            }
                            _ => break,
                        }
                        // stop at statement end
                        if matches!(self.peek(), Some(T::Newline) | Some(T::Semi) | Some(T::RBrace))
                        {
                            break;
                        }
                    }
                    ty = parts.join(" ");
                }
                "elements" => {
                    self.pos += 1;
                    let _ = self.eat(&T::Word("=".into()));
                    if self.eat(&T::LBrace) {
                        // items separated by commas; take first word of each item
                        let mut want_item = true;
                        loop {
                            match self.peek() {
                                None => break,
                                Some(T::RBrace) => {
                                    self.pos += 1;
                                    break;
                                }
                                Some(T::Newline) => {
                                    self.pos += 1;
                                }
                                Some(T::Comma) => {
                                    want_item = true;
                                    self.pos += 1;
                                }
                                Some(T::Word(w)) => {
                                    if want_item {
                                        elements.push(w.clone());
                                        want_item = false;
                                    }
                                    self.pos += 1;
                                }
                                Some(T::Str(s)) => {
                                    if want_item {
                                        elements.push(format!("\"{s}\""));
                                        want_item = false;
                                    }
                                    self.pos += 1;
                                }
                                _ => {
                                    self.pos += 1;
                                }
                            }
                        }
                    }
                }
                _ => self.skip_stmt(),
            }
        }
        let set = match ty.as_str() {
            "ipv4_addr" => {
                let ivs: Vec<(u128, u128)> = elements
                    .iter()
                    .filter_map(|e| parse_addr_spec(e))
                    .map(|(_, lo, hi)| (lo, hi))
                    .collect();
                NamedSet::Addrs(Family::V4, IntervalSet::from_unsorted(ivs))
            }
            "ipv6_addr" => {
                let ivs: Vec<(u128, u128)> = elements
                    .iter()
                    .filter_map(|e| parse_addr_spec(e))
                    .map(|(_, lo, hi)| (lo, hi))
                    .collect();
                NamedSet::Addrs(Family::V6, IntervalSet::from_unsorted(ivs))
            }
            "inet_service" => {
                let ivs: Vec<(u128, u128)> = elements
                    .iter()
                    .filter_map(|e| parse_port_range(e))
                    .map(|(lo, hi)| (lo as u128, hi as u128))
                    .collect();
                NamedSet::Ports(IntervalSet::from_unsorted(ivs))
            }
            t if t.contains("ifname") || t.contains("iface") => {
                NamedSet::Ifaces(elements.iter().map(|e| e.trim_matches('"').to_string()).collect())
            }
            _ => NamedSet::Other,
        };
        self.sets.insert((table.to_string(), name.to_string()), set);
    }

    fn parse_chain_body(&mut self, table: &str, name: &str, pending: &mut Vec<PendingRule>) {
        let cidx = self.rs.get_or_add_chain(table, name);
        loop {
            self.skip_separators();
            match self.peek() {
                None => return,
                Some(T::RBrace) => {
                    self.pos += 1;
                    return;
                }
                _ => {}
            }
            // collect one statement (to newline or semicolon)
            let start = self.pos;
            let mut depth = 0i32;
            while let Some(t) = self.peek() {
                match t {
                    T::LBrace | T::LParen => depth += 1,
                    T::RBrace | T::RParen => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    T::Newline | T::Semi if depth == 0 => break,
                    _ => {}
                }
                self.pos += 1;
            }
            let stmt: Vec<T> = self.toks[start..self.pos].to_vec();
            // consume the terminator
            if matches!(self.peek(), Some(T::Newline) | Some(T::Semi)) {
                self.pos += 1;
            }
            if stmt.is_empty() {
                continue;
            }
            let head = match &stmt[0] {
                T::Word(w) => w.as_str(),
                _ => "",
            };
            match head {
                "type" => {
                    self.rs.chains[cidx].builtin = true;
                }
                "policy" => {
                    if let Some(T::Word(p)) = stmt.get(1) {
                        self.rs.chains[cidx].policy = Some(p.to_ascii_uppercase());
                    }
                }
                "hook" | "priority" | "device" | "flags" | "devices" => {}
                _ => {
                    let text = stmt_text(&stmt);
                    match self.parse_rule(table, &stmt) {
                        Some(builder) => pending.push(PendingRule {
                            table: table.to_string(),
                            chain: name.to_string(),
                            builder,
                            text,
                        }),
                        None => {
                            self.rs.warn(format!(
                                "{}: unparsable nft rule kept opaque: {text}",
                                self.origin
                            ));
                            let mut b = RuleBuilder::new();
                            b.atoms.push(format!("unparsed: {text}"));
                            b.target = Some(("log".into(), false));
                            pending.push(PendingRule {
                                table: table.to_string(),
                                chain: name.to_string(),
                                builder: b,
                                text,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Parse one rule statement. Returns None on hard failure.
    fn parse_rule(&mut self, table: &str, stmt: &[T]) -> Option<RuleBuilder> {
        let mut b = RuleBuilder::new();
        let mut i = 0usize;
        fn kw(t: &T) -> &str {
            match t {
                T::Word(w) => w.as_str(),
                T::Str(s) => s.as_str(),
                _ => "",
            }
        }
        while i < stmt.len() {
            let w = kw(&stmt[i]).to_string();
            match w.as_str() {
                "ip" | "ip6" => {
                    let fam = if w == "ip" { Family::V4 } else { Family::V6 };
                    let field = kw(stmt.get(i + 1)?).to_string();
                    match field.as_str() {
                        "saddr" | "daddr" => {
                            let (ni, set) = self.addr_value(table, stmt, i + 2, fam)?;
                            b.set_family(fam);
                            if field == "saddr" {
                                b.src = Some((fam, set));
                            } else {
                                b.dst = Some((fam, set));
                            }
                            i = ni;
                        }
                        "protocol" | "nexthdr" => {
                            let (ni, set) = proto_value(stmt, i + 2)?;
                            b.proto = Some(match &b.proto {
                                Some(p) => p.intersect(&set),
                                None => set,
                            });
                            i = ni;
                        }
                        other => {
                            b.atoms.push(format!("{w} {other}"));
                            i = skip_value(stmt, i + 2);
                        }
                    }
                }
                "meta" => {
                    let field = kw(stmt.get(i + 1)?).to_string();
                    match field.as_str() {
                        "l4proto" => {
                            let (ni, set) = proto_value(stmt, i + 2)?;
                            b.proto = Some(match &b.proto {
                                Some(p) => p.intersect(&set),
                                None => set,
                            });
                            i = ni;
                        }
                        "iifname" | "iif" | "oifname" | "oif" => {
                            let (ni, name, negated) = iface_value(stmt, i + 2);
                            if negated {
                                b.atoms.push(format!("{field} != {name}"));
                            } else if field.starts_with('i') {
                                b.iif = Some(name);
                            } else {
                                b.oif = Some(name);
                            }
                            i = ni;
                        }
                        other => {
                            b.atoms.push(format!("meta {other}"));
                            i = skip_value(stmt, i + 2);
                        }
                    }
                }
                "iif" | "iifname" | "oif" | "oifname" => {
                    let (ni, name, negated) = iface_value(stmt, i + 1);
                    if negated {
                        b.atoms.push(format!("{w} != {name}"));
                    } else if w.starts_with('i') {
                        b.iif = Some(name);
                    } else {
                        b.oif = Some(name);
                    }
                    i = ni;
                }
                "tcp" | "udp" | "sctp" | "udplite" | "dccp" => {
                    let pn = proto_number(&w);
                    if let Some(n) = pn {
                        let set = IntervalSet::single(n as u128, n as u128);
                        b.proto = Some(match &b.proto {
                            Some(p) => p.intersect(&set),
                            None => set,
                        });
                    }
                    let field = kw(stmt.get(i + 1)?).to_string();
                    match field.as_str() {
                        "sport" | "dport" => {
                            let (ni, set) = self.port_value(table, stmt, i + 2)?;
                            if field == "sport" {
                                b.sport = Some(set);
                            } else {
                                b.dport = Some(set);
                            }
                            i = ni;
                        }
                        other => {
                            b.atoms.push(format!("{w} {other}"));
                            i = skip_value(stmt, i + 2);
                        }
                    }
                }
                "ct" => {
                    let field = kw(stmt.get(i + 1)?).to_string();
                    // collect "state established,related" style values
                    let mut j = i + 2;
                    let mut vals = Vec::new();
                    while j < stmt.len() {
                        match &stmt[j] {
                            T::Word(x) if x != "==" && x != "!=" && !is_keyword(x) => {
                                vals.push(x.clone());
                                j += 1;
                            }
                            T::Comma => j += 1,
                            _ => break,
                        }
                    }
                    b.atoms.push(format!("ct {field} {}", vals.join(",")));
                    i = j.max(i + 2);
                }
                "counter" => {
                    // optional "packets N bytes N"
                    let mut j = i + 1;
                    loop {
                        match stmt.get(j) {
                            Some(T::Word(x)) if x == "packets" || x == "bytes" => j += 2,
                            Some(T::Word(x)) if x.parse::<u64>().is_ok() => j += 1,
                            _ => break,
                        }
                    }
                    i = j;
                }
                "accept" | "drop" | "notrack" => {
                    b.target = Some((w, false));
                    i += 1;
                }
                "reject" => {
                    b.target = Some(("reject".into(), false));
                    i += 1;
                    // optional "with tcp reset" etc.
                    if kw(stmt.get(i).unwrap_or(&T::Semi)) == "with" {
                        i += 1;
                        while i < stmt.len() && !is_keyword(kw(&stmt[i])) {
                            i += 1;
                        }
                    }
                }
                "return" => {
                    b.target = Some(("return".into(), false));
                    i += 1;
                }
                "jump" | "goto" => {
                    let name = self.take_word_from(stmt, i + 1)?;
                    b.target = Some((name, w == "goto"));
                    i = stmt.len(); // verdict ends the rule
                }
                "log" => {
                    b.target.get_or_insert(("log".into(), false));
                    i += 1;
                    // skip log options
                    while i < stmt.len() {
                        match kw(&stmt[i]) {
                            "prefix" | "level" | "group" | "snaplen" | "queue-threshold"
                            | "flags" => i += 2,
                            _ => break,
                        }
                    }
                }
                "masquerade" | "snat" | "dnat" | "redirect" | "queue" => {
                    b.target = Some((w, false));
                    i += 1;
                    if kw(stmt.get(i).unwrap_or(&T::Semi)) == "to" {
                        i += 1;
                        // skip the nat address/port spec (one token, maybe a set)
                        i = skip_value(stmt, i);
                    }
                }
                "limit" => {
                    b.atoms.push("limit".into());
                    i += 1;
                    while i < stmt.len() {
                        match kw(&stmt[i]) {
                            "rate" | "burst" => i += 2,
                            "over" | "until" => i += 1,
                            _ => break,
                        }
                    }
                }
                "comment" => {
                    i += 2; // comment string
                }
                "flow" | "synproxy" | "tproxy" => {
                    b.atoms.push(w.clone());
                    i = skip_value(stmt, i + 1);
                }
                "" => {
                    i += 1; // stray punctuation inside rule
                }
                other => {
                    // unknown expression: opaque predicate, skip its value
                    b.atoms.push(other.to_string());
                    i = skip_value(stmt, i + 1);
                }
            }
        }
        Some(b)
    }

    fn take_word_from(&self, stmt: &[T], i: usize) -> Option<String> {
        match stmt.get(i) {
            Some(T::Word(w)) => Some(w.clone()),
            Some(T::Str(s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Parse "saddr/daddr" value starting at stmt[i]: optional "!=",
    /// then CIDR | range | { set } | @named.
    fn addr_value(
        &self,
        table: &str,
        stmt: &[T],
        mut i: usize,
        fam: Family,
    ) -> Option<(usize, IntervalSet)> {
        let mut negate = false;
        if matches!(stmt.get(i), Some(T::Word(w)) if w == "!=") {
            negate = true;
            i += 1;
        }
        let full = IntervalSet::full(fam.addr_max());
        let set = match stmt.get(i)? {
            T::LBrace => {
                let mut ivs = Vec::new();
                let mut j = i + 1;
                while j < stmt.len() && stmt[j] != T::RBrace {
                    if let T::Word(w) = &stmt[j] {
                        if let Some((f, lo, hi)) = parse_addr_spec(w) {
                            if f == fam {
                                ivs.push((lo, hi));
                            }
                        }
                    }
                    j += 1;
                }
                i = j + 1; // past RBrace
                IntervalSet::from_unsorted(ivs)
            }
            T::Word(w) if w.starts_with('@') => {
                let name = &w[1..];
                i += 1;
                match self.sets.get(&(table.to_string(), name.to_string())) {
                    Some(NamedSet::Addrs(sf, ivs)) if *sf == fam => ivs.clone(),
                    _ => return Some((i, full)), // unknown set: no constraint (warned elsewhere)
                }
            }
            T::Word(w) | T::Str(w) => {
                i += 1;
                let (f, lo, hi) = parse_addr_spec(w)?;
                if f != fam {
                    return Some((i, full));
                }
                IntervalSet::single(lo, hi)
            }
            _ => return None,
        };
        let set = if negate { full.subtract(&set) } else { set };
        Some((i, set))
    }

    fn port_value(&self, table: &str, stmt: &[T], mut i: usize) -> Option<(usize, IntervalSet)> {
        let mut negate = false;
        if matches!(stmt.get(i), Some(T::Word(w)) if w == "!=") {
            negate = true;
            i += 1;
        }
        let full = IntervalSet::full(65535);
        let set = match stmt.get(i)? {
            T::LBrace => {
                let mut ivs = Vec::new();
                let mut j = i + 1;
                while j < stmt.len() && stmt[j] != T::RBrace {
                    if let T::Word(w) = &stmt[j] {
                        if let Some((lo, hi)) = parse_port_range(w) {
                            ivs.push((lo as u128, hi as u128));
                        }
                    }
                    j += 1;
                }
                i = j + 1;
                IntervalSet::from_unsorted(ivs)
            }
            T::Word(w) if w.starts_with('@') => {
                let name = &w[1..];
                i += 1;
                match self.sets.get(&(table.to_string(), name.to_string())) {
                    Some(NamedSet::Ports(ivs)) => ivs.clone(),
                    _ => return Some((i, full)),
                }
            }
            T::Word(w) | T::Str(w) => {
                i += 1;
                let (lo, hi) = parse_port_range(w)?;
                IntervalSet::single(lo as u128, hi as u128)
            }
            _ => return None,
        };
        let set = if negate { full.subtract(&set) } else { set };
        Some((i, set))
    }
}

fn proto_value(stmt: &[T], mut i: usize) -> Option<(usize, IntervalSet)> {
    let mut negate = false;
    if matches!(stmt.get(i), Some(T::Word(w)) if w == "!=") {
        negate = true;
        i += 1;
    }
    let full = IntervalSet::full(255);
    let set = match stmt.get(i)? {
        T::LBrace => {
            let mut ivs = Vec::new();
            let mut j = i + 1;
            while j < stmt.len() && stmt[j] != T::RBrace {
                if let T::Word(w) = &stmt[j] {
                    if let Some(n) = proto_number(w) {
                        ivs.push((n as u128, n as u128));
                    }
                }
                j += 1;
            }
            i = j + 1;
            IntervalSet::from_unsorted(ivs)
        }
        T::Word(w) | T::Str(w) => {
            i += 1;
            let n = proto_number(w)?;
            IntervalSet::single(n as u128, n as u128)
        }
        _ => return None,
    };
    let set = if negate { full.subtract(&set) } else { set };
    Some((i, set))
}

fn iface_value(stmt: &[T], mut i: usize) -> (usize, String, bool) {
    let mut negate = false;
    if matches!(stmt.get(i), Some(T::Word(w)) if w == "!=") {
        negate = true;
        i += 1;
    }
    let name = match stmt.get(i) {
        Some(T::Word(w)) => w.clone(),
        Some(T::Str(s)) => s.clone(),
        _ => String::new(),
    };
    (i + 1, name, negate)
}

/// Skip one value: a word, a string, a balanced { } or ( ) group.
fn skip_value(stmt: &[T], i: usize) -> usize {
    match stmt.get(i) {
        Some(T::LBrace) | Some(T::LParen) => {
            let close = if stmt[i] == T::LBrace { T::RBrace } else { T::RParen };
            let mut depth = 0i32;
            let mut j = i;
            while j < stmt.len() {
                if stmt[j] == stmt[i] {
                    depth += 1;
                } else if stmt[j] == close {
                    depth -= 1;
                    if depth == 0 {
                        return j + 1;
                    }
                }
                j += 1;
            }
            j
        }
        Some(T::Word(_)) | Some(T::Str(_)) => i + 1,
        _ => i,
    }
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "accept" | "drop" | "reject" | "return" | "jump" | "goto" | "log" | "ip" | "ip6" | "tcp"
            | "udp" | "sctp" | "meta" | "ct" | "counter" | "comment" | "masquerade" | "snat"
            | "dnat" | "redirect" | "limit" | "iif" | "oif" | "iifname" | "oifname" | "queue"
            | "notrack"
    )
}

fn stmt_text(stmt: &[T]) -> String {
    let mut s = String::new();
    for t in stmt {
        match t {
            T::Word(w) => {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push_str(w);
            }
            T::Str(v) => {
                if !s.is_empty() {
                    s.push(' ');
                }
                s.push('"');
                s.push_str(v);
                s.push('"');
            }
            T::LBrace => s.push_str(" { "),
            T::RBrace => s.push_str(" }"),
            T::LParen => s.push_str("( "),
            T::RParen => s.push_str(" )"),
            T::Semi => s.push_str("; "),
            T::Comma => {
                s.push(',');
                s.push(' ');
            }
            T::Newline => {}
        }
    }
    s.trim().to_string()
}
