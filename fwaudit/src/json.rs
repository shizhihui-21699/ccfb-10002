//! Minimal JSON writer (no external deps).

pub enum J {
    Obj(Vec<(String, J)>),
    Arr(Vec<J>),
    Str(String),
    Num(u64),
    Bool(bool),
    Null,
}

impl J {
    pub fn obj() -> J {
        J::Obj(Vec::new())
    }
    pub fn put(&mut self, k: &str, v: J) {
        if let J::Obj(m) = self {
            m.push((k.to_string(), v));
        }
    }
    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }
    pub fn arr<I: IntoIterator<Item = J>>(it: I) -> J {
        J::Arr(it.into_iter().collect())
    }
}

pub fn render(j: &J) -> String {
    let mut s = String::new();
    write_j(j, 0, &mut s);
    s.push('\n');
    s
}

fn indent(n: usize, out: &mut String) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

fn write_j(j: &J, depth: usize, out: &mut String) {
    match j {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Str(s) => write_str(s, out),
        J::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, it) in items.iter().enumerate() {
                indent(depth + 1, out);
                write_j(it, depth + 1, out);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(depth, out);
            out.push(']');
        }
        J::Obj(kv) => {
            if kv.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in kv.iter().enumerate() {
                indent(depth + 1, out);
                write_str(k, out);
                out.push_str(": ");
                write_j(v, depth + 1, out);
                if i + 1 < kv.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(depth, out);
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
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
    out.push('"');
}
