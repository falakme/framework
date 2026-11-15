//! Helpers that turn a parsed YAML [`Node`] into typed values and report every problem
//! with a position, instead of stopping at the first one.

use std::collections::HashSet;

use crate::{
    diagnostics::{Diagnostic, Position},
    yaml::{Entry, Node, Value},
};

/// Collects diagnostics for one file.
pub struct Ctx<'a> {
    pub file: &'a str,
    pub diags: &'a mut Vec<Diagnostic>,
}

impl Ctx<'_> {
    pub fn error(&mut self, code: &'static str, position: Position, message: impl Into<String>) {
        self.diags
            .push(Diagnostic::error(code, self.file, position, message));
    }

    pub fn error_help(
        &mut self,
        code: &'static str,
        position: Position,
        message: impl Into<String>,
        help: impl Into<String>,
    ) {
        self.diags
            .push(Diagnostic::error(code, self.file, position, message).with_suggestion(help));
    }

    pub fn warn(&mut self, code: &'static str, position: Position, message: impl Into<String>) {
        let mut d = Diagnostic::error(code, self.file, position, message);
        d.severity = crate::diagnostics::Severity::Warning;
        self.diags.push(d);
    }
}

pub fn kind_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Int(_) => "an integer",
        Value::Float(_) => "a number",
        Value::Str(_) => "a string",
        Value::Seq(_) => "a list",
        Value::Map(_) => "a mapping",
    }
}

/// `^[a-z][a-z0-9_]{0,62}$`
pub fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && s.len() <= 63
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

/// `^[a-z][a-z0-9_-]{1,39}$`
pub fn is_app_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && (2..=40).contains(&s.len())
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Closest candidate within two edits, for "did you mean" help.
pub fn closest<'a>(word: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (edit_distance(word, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// A mapping being read. Every key must be taken or allowed; leftovers are errors.
pub struct MapReader<'n> {
    pub position: Position,
    entries: &'n [Entry],
    taken: HashSet<&'n str>,
    allowed: &'static [&'static str],
}

impl<'n> MapReader<'n> {
    /// Returns `None` (after reporting) if the node is not a mapping.
    pub fn new(
        ctx: &mut Ctx,
        node: &'n Node,
        what: &str,
        allowed: &'static [&'static str],
    ) -> Option<Self> {
        match &node.value {
            Value::Map(entries) => Some(Self {
                position: node.position,
                entries,
                taken: HashSet::new(),
                allowed,
            }),
            other => {
                ctx.error(
                    "expected_mapping",
                    node.position,
                    format!("{what} must be a mapping, found {}", kind_name(other)),
                );
                None
            }
        }
    }

    pub fn take(&mut self, key: &'static str) -> Option<&'n Node> {
        let e = self.entries.iter().find(|e| e.key == key)?;
        self.taken.insert(key);
        Some(&e.value)
    }

    pub fn require(&mut self, ctx: &mut Ctx, key: &'static str) -> Option<&'n Node> {
        let found = self.take(key);
        if found.is_none() {
            ctx.error_help(
                "missing_key",
                self.position,
                format!("missing required key `{key}`"),
                format!("add `{key}:`"),
            );
        }
        found
    }

    /// Report keys that were neither taken nor allowed.
    pub fn finish(self, ctx: &mut Ctx) {
        for e in self.entries {
            if self.taken.contains(e.key.as_str()) || self.allowed.contains(&e.key.as_str()) {
                continue;
            }
            let help = match closest(&e.key, self.allowed) {
                Some(c) => format!("did you mean `{c}`?"),
                None => format!("allowed keys: {}", self.allowed.join(", ")),
            };
            ctx.error_help(
                "unknown_key",
                e.key_position,
                format!("unknown key `{}`", e.key),
                help,
            );
        }
    }

    pub fn entries(&self) -> &'n [Entry] {
        self.entries
    }
}

pub fn read_str<'n>(ctx: &mut Ctx, node: &'n Node, what: &str) -> Option<&'n str> {
    match &node.value {
        Value::Str(s) => Some(s),
        other => {
            ctx.error(
                "wrong_type",
                node.position,
                format!("{what} must be a string, found {}", kind_name(other)),
            );
            None
        }
    }
}

pub fn read_bool(ctx: &mut Ctx, node: &Node, what: &str) -> Option<bool> {
    match &node.value {
        Value::Bool(b) => Some(*b),
        other => {
            ctx.error_help(
                "wrong_type",
                node.position,
                format!("{what} must be true or false, found {}", kind_name(other)),
                "use `true` or `false` (words like `yes` are strings)",
            );
            None
        }
    }
}

pub fn read_int(ctx: &mut Ctx, node: &Node, what: &str) -> Option<i64> {
    match &node.value {
        Value::Int(i) => Some(*i),
        other => {
            ctx.error(
                "wrong_type",
                node.position,
                format!("{what} must be an integer, found {}", kind_name(other)),
            );
            None
        }
    }
}

pub fn read_u32(ctx: &mut Ctx, node: &Node, what: &str, min: u32, max: u32) -> Option<u32> {
    let i = read_int(ctx, node, what)?;
    match u32::try_from(i) {
        Ok(v) if (min..=max).contains(&v) => Some(v),
        _ => {
            ctx.error(
                "out_of_range",
                node.position,
                format!("{what} must be between {min} and {max}, found {i}"),
            );
            None
        }
    }
}

/// An identifier matching the name pattern.
pub fn read_name(ctx: &mut Ctx, node: &Node, what: &str) -> Option<String> {
    let s = read_str(ctx, node, what)?;
    if is_name(s) {
        Some(s.to_string())
    } else {
        ctx.error_help(
            "invalid_name",
            node.position,
            format!("{what} `{s}` is not a valid name"),
            "use lowercase letters, digits and underscores, starting with a letter (at most 63 characters)",
        );
        None
    }
}

/// A list of items read by `item`. Reports duplicates through `dup_what`.
pub fn read_list<'n, T: PartialEq>(
    ctx: &mut Ctx,
    node: &'n Node,
    what: &str,
    mut item: impl FnMut(&mut Ctx, &'n Node) -> Option<T>,
) -> Vec<T> {
    let Value::Seq(items) = &node.value else {
        ctx.error(
            "wrong_type",
            node.position,
            format!("{what} must be a list, found {}", kind_name(&node.value)),
        );
        return Vec::new();
    };
    let mut out: Vec<T> = Vec::new();
    for n in items {
        if let Some(v) = item(ctx, n) {
            if out.contains(&v) {
                ctx.error(
                    "duplicate_item",
                    n.position,
                    format!("duplicate entry in {what}"),
                );
            } else {
                out.push(v);
            }
        }
    }
    out
}
