//! Strict YAML reader implementing the subset in SCHEMA_SPECIFICATION §2.
//!
//! It rejects duplicate keys, anchors, aliases, merge keys, tags, multiple documents,
//! non-string keys and oversized input, each with an exact position. Scalars follow the
//! YAML 1.2 core schema, so only `true` and `false` are booleans.

use std::collections::HashSet;

use saphyr_parser::{Event, Parser, ScalarStyle};

use crate::diagnostics::{Diagnostic, Position};

pub const MAX_BYTES: usize = 256 * 1024;
pub const MAX_DEPTH: usize = 16;
pub const MAX_ITEMS: usize = 1000;

/// A parsed value with the position where it starts.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub position: Position,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Node>),
    /// Entries in source order. Keys are unique.
    Map(Vec<Entry>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub key: String,
    pub key_position: Position,
    pub value: Node,
}

impl Node {
    pub fn as_map(&self) -> Option<&[Entry]> {
        match &self.value {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Look up a key in a mapping node.
    pub fn get(&self, key: &str) -> Option<&Node> {
        self.as_map()?
            .iter()
            .find(|e| e.key == key)
            .map(|e| &e.value)
    }
}

enum Frame {
    Seq {
        position: Position,
        items: Vec<Node>,
    },
    Map {
        position: Position,
        entries: Vec<Entry>,
        seen: HashSet<String>,
        key: Option<(String, Position)>,
    },
}

fn pos(span: saphyr_parser::Span) -> Position {
    Position {
        line: span.start.line() as u32,
        column: span.start.col() as u32 + 1,
    }
}

/// Parse one YAML document. `file` is used only in diagnostics.
///
/// Returns every problem found, not just the first, except that a syntax error or a
/// structural limit stops parsing because later events cannot be trusted.
pub fn parse(file: &str, source: &str) -> Result<Node, Vec<Diagnostic>> {
    let mut diags: Vec<Diagnostic> = Vec::new();
    let origin = Position { line: 1, column: 1 };

    if source.len() > MAX_BYTES {
        return Err(vec![
            Diagnostic::error(
                "yaml_too_large",
                file,
                origin,
                format!("file is {} bytes; the limit is {MAX_BYTES}", source.len()),
            )
            .with_suggestion("split the content across several files"),
        ]);
    }

    let mut parser = Parser::new_from_str(source).keep_tags(true);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Node> = None;
    let mut documents = 0;

    loop {
        let (event, span) = match parser.next_event() {
            None => break,
            Some(Ok(pair)) => pair,
            Some(Err(e)) => {
                diags.push(Diagnostic::error(
                    "yaml_syntax",
                    file,
                    Position {
                        line: e.marker().line() as u32,
                        column: e.marker().col() as u32 + 1,
                    },
                    e.info().to_string(),
                ));
                return Err(diags);
            }
        };
        let here = pos(span);
        let is_map = matches!(&event, Event::MappingStart(..));

        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                documents += 1;
                if documents > 1 {
                    diags.push(
                        Diagnostic::error(
                            "yaml_multi_document",
                            file,
                            here,
                            "a file may contain only one YAML document",
                        )
                        .with_suggestion(
                            "remove the extra `---` and put the content in a separate file",
                        ),
                    );
                    return Err(diags);
                }
            }
            Event::Alias(_) => {
                diags.push(
                    Diagnostic::error(
                        "yaml_alias",
                        file,
                        here,
                        "aliases (`*name`) are not allowed",
                    )
                    .with_suggestion("write the value out in full"),
                );
                place(
                    &mut stack,
                    &mut root,
                    Node {
                        position: here,
                        value: Value::Null,
                    },
                    file,
                    &mut diags,
                );
            }
            Event::Scalar(text, style, anchor, tag) => {
                if anchor != 0 {
                    diags.push(
                        Diagnostic::error(
                            "yaml_anchor",
                            file,
                            here,
                            "anchors (`&name`) are not allowed",
                        )
                        .with_suggestion("remove the anchor and write the value out in full"),
                    );
                }
                if let Some(t) = &tag {
                    diags.push(
                        Diagnostic::error(
                            "yaml_tag",
                            file,
                            here,
                            format!("tags are not allowed (found `{}{}`)", t.handle, t.suffix),
                        )
                        .with_suggestion("remove the tag"),
                    );
                }
                let in_key_slot = matches!(stack.last(), Some(Frame::Map { key: None, .. }));
                if in_key_slot {
                    let plain = matches!(style, ScalarStyle::Plain);
                    if text == "<<" && plain {
                        diags.push(
                            Diagnostic::error(
                                "yaml_merge_key",
                                file,
                                here,
                                "merge keys (`<<`) are not allowed",
                            )
                            .with_suggestion("list the keys explicitly"),
                        );
                    }
                    let resolved = if plain {
                        resolve_plain(&text)
                    } else {
                        Resolved::Str
                    };
                    if !matches!(resolved, Resolved::Str) {
                        diags.push(
                            Diagnostic::error(
                                "yaml_non_string_key",
                                file,
                                here,
                                format!("mapping key `{text}` is not a string"),
                            )
                            .with_suggestion(format!("quote it: \"{text}\"")),
                        );
                    }
                    if let Some(Frame::Map { key, .. }) = stack.last_mut() {
                        *key = Some((text.into_owned(), here));
                    }
                    continue;
                }
                let value = match style {
                    ScalarStyle::Plain => match resolve_plain(&text) {
                        Resolved::Null => Value::Null,
                        Resolved::Bool(b) => Value::Bool(b),
                        Resolved::Int(i) => Value::Int(i),
                        Resolved::Float(f) => Value::Float(f),
                        Resolved::IntOutOfRange => {
                            diags.push(Diagnostic::error(
                                "yaml_int_range",
                                file,
                                here,
                                format!("integer `{text}` does not fit in 64 bits"),
                            ));
                            Value::Null
                        }
                        Resolved::Str => Value::Str(text.into_owned()),
                    },
                    _ => Value::Str(text.into_owned()),
                };
                place(
                    &mut stack,
                    &mut root,
                    Node {
                        position: here,
                        value,
                    },
                    file,
                    &mut diags,
                );
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                if anchor != 0 {
                    diags.push(
                        Diagnostic::error(
                            "yaml_anchor",
                            file,
                            here,
                            "anchors (`&name`) are not allowed",
                        )
                        .with_suggestion("remove the anchor and write the value out in full"),
                    );
                }
                if let Some(t) = &tag {
                    diags.push(
                        Diagnostic::error(
                            "yaml_tag",
                            file,
                            here,
                            format!("tags are not allowed (found `{}{}`)", t.handle, t.suffix),
                        )
                        .with_suggestion("remove the tag"),
                    );
                }
                if matches!(stack.last(), Some(Frame::Map { key: None, .. })) {
                    diags.push(Diagnostic::error(
                        "yaml_non_string_key",
                        file,
                        here,
                        "a mapping key must be a string, not a list or mapping",
                    ));
                    return Err(diags);
                }
                if stack.len() >= MAX_DEPTH {
                    diags.push(Diagnostic::error(
                        "yaml_too_deep",
                        file,
                        here,
                        format!("nesting is deeper than {MAX_DEPTH} levels"),
                    ));
                    return Err(diags);
                }
                stack.push(if is_map {
                    Frame::Map {
                        position: here,
                        entries: Vec::new(),
                        seen: HashSet::new(),
                        key: None,
                    }
                } else {
                    Frame::Seq {
                        position: here,
                        items: Vec::new(),
                    }
                });
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let node = match stack.pop() {
                    Some(Frame::Seq { position, items }) => Node {
                        position,
                        value: Value::Seq(items),
                    },
                    Some(Frame::Map {
                        position, entries, ..
                    }) => Node {
                        position,
                        value: Value::Map(entries),
                    },
                    None => continue,
                };
                place(&mut stack, &mut root, node, file, &mut diags);
            }
        }
    }

    match (root, diags.is_empty()) {
        (Some(node), true) => Ok(node),
        (None, true) => Err(vec![Diagnostic::error(
            "yaml_empty",
            file,
            origin,
            "the file is empty",
        )]),
        (_, false) => Err(diags),
    }
}

/// Attach a finished value to its parent, or make it the root.
fn place(
    stack: &mut [Frame],
    root: &mut Option<Node>,
    node: Node,
    file: &str,
    diags: &mut Vec<Diagnostic>,
) {
    match stack.last_mut() {
        None => *root = Some(node),
        Some(Frame::Seq { items, .. }) => {
            if items.len() >= MAX_ITEMS {
                if items.len() == MAX_ITEMS {
                    diags.push(Diagnostic::error(
                        "yaml_too_many_items",
                        file,
                        node.position,
                        format!("a list may have at most {MAX_ITEMS} items"),
                    ));
                }
                items.push(Node {
                    position: node.position,
                    value: Value::Null,
                });
                return;
            }
            items.push(node);
        }
        Some(Frame::Map {
            entries, seen, key, ..
        }) => {
            let Some((k, key_position)) = key.take() else {
                return;
            };
            if entries.len() >= MAX_ITEMS {
                if entries.len() == MAX_ITEMS {
                    diags.push(Diagnostic::error(
                        "yaml_too_many_items",
                        file,
                        key_position,
                        format!("a mapping may have at most {MAX_ITEMS} keys"),
                    ));
                }
                return;
            }
            if !seen.insert(k.clone()) {
                diags.push(
                    Diagnostic::error(
                        "yaml_duplicate_key",
                        file,
                        key_position,
                        format!("duplicate key `{k}`"),
                    )
                    .with_suggestion("remove one of them or rename it"),
                );
                return;
            }
            entries.push(Entry {
                key: k,
                key_position,
                value: node,
            });
        }
    }
}

enum Resolved {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    IntOutOfRange,
    Str,
}

/// YAML 1.2 core schema resolution for a plain scalar.
fn resolve_plain(text: &str) -> Resolved {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Resolved::Null,
        "true" | "True" | "TRUE" => return Resolved::Bool(true),
        "false" | "False" | "FALSE" => return Resolved::Bool(false),
        _ => {}
    }
    let (sign, digits) = match text.as_bytes().first() {
        Some(b'+') => (1i128, &text[1..]),
        Some(b'-') => (-1i128, &text[1..]),
        _ => (1i128, text),
    };
    if digits.is_empty() {
        return Resolved::Str;
    }
    let radix_body = |prefix: &str, radix: u32| -> Option<Resolved> {
        let body = digits.strip_prefix(prefix)?;
        if body.is_empty() || !body.chars().all(|c| c.is_digit(radix)) {
            return None;
        }
        Some(match i128::from_str_radix(body, radix) {
            Ok(n) => to_i64(sign * n),
            Err(_) => Resolved::IntOutOfRange,
        })
    };
    if sign == 1 && !text.starts_with('+') {
        if let Some(r) = radix_body("0x", 16).or_else(|| radix_body("0o", 8)) {
            return r;
        }
    }
    if digits.bytes().all(|b| b.is_ascii_digit()) {
        return match digits.parse::<i128>() {
            Ok(n) => to_i64(sign * n),
            Err(_) => Resolved::IntOutOfRange,
        };
    }
    // Float: must start with a digit or a dot, so Rust's `inf` and `nan` words stay strings.
    let first = digits.as_bytes()[0];
    if (first.is_ascii_digit() || first == b'.')
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        && let Ok(f) = text.parse::<f64>()
    {
        return Resolved::Float(f);
    }
    Resolved::Str
}

fn to_i64(n: i128) -> Resolved {
    i64::try_from(n).map_or(Resolved::IntOutOfRange, Resolved::Int)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(src: &str) -> Vec<(&'static str, u32, u32)> {
        parse("t.yaml", src)
            .unwrap_err()
            .iter()
            .map(|d| (d.code, d.position.line, d.position.column))
            .collect()
    }

    #[test]
    fn parses_a_normal_file_with_positions() {
        let n = parse(
            "t.yaml",
            "schema_version: 1\nname: demo\nlist: [a, 2, true]\n",
        )
        .unwrap();
        assert_eq!(n.get("schema_version").unwrap().value, Value::Int(1));
        assert_eq!(n.get("name").unwrap().value, Value::Str("demo".into()));
        let list = n.get("list").unwrap();
        assert_eq!(list.position, Position { line: 3, column: 7 });
        let Value::Seq(items) = &list.value else {
            panic!()
        };
        assert_eq!(items[1].value, Value::Int(2));
        assert_eq!(items[2].value, Value::Bool(true));
    }

    #[test]
    fn yes_and_no_are_strings_and_quotes_force_strings() {
        let n = parse("t.yaml", "a: yes\nb: no\nc: \"1.0\"\nd: null\ne: '~'\n").unwrap();
        assert_eq!(n.get("a").unwrap().value, Value::Str("yes".into()));
        assert_eq!(n.get("b").unwrap().value, Value::Str("no".into()));
        assert_eq!(n.get("c").unwrap().value, Value::Str("1.0".into()));
        assert_eq!(n.get("d").unwrap().value, Value::Null);
        assert_eq!(n.get("e").unwrap().value, Value::Str("~".into()));
    }

    #[test]
    fn numbers_resolve_per_core_schema() {
        let n = parse("t.yaml", "a: -12\nb: 0x1F\nc: 1.5\nd: inf\ne: .5\n").unwrap();
        assert_eq!(n.get("a").unwrap().value, Value::Int(-12));
        assert_eq!(n.get("b").unwrap().value, Value::Int(31));
        assert_eq!(n.get("c").unwrap().value, Value::Float(1.5));
        assert_eq!(n.get("d").unwrap().value, Value::Str("inf".into()));
        assert_eq!(n.get("e").unwrap().value, Value::Float(0.5));
    }

    #[test]
    fn rejects_duplicate_keys_at_the_second_one() {
        assert_eq!(
            codes("a: 1\nb: 2\na: 3\n"),
            vec![("yaml_duplicate_key", 3, 1)]
        );
    }

    #[test]
    fn rejects_anchors_aliases_and_merge_keys() {
        let c = codes("base: &b\n  x: 1\nother:\n  <<: *b\n");
        let names: Vec<_> = c.iter().map(|c| c.0).collect();
        assert!(names.contains(&"yaml_anchor"));
        assert!(names.contains(&"yaml_alias"));
        assert!(names.contains(&"yaml_merge_key"));
    }

    #[test]
    fn rejects_tags_multi_document_and_non_string_keys() {
        assert_eq!(codes("a: !!str 1\n")[0].0, "yaml_tag");
        assert_eq!(codes("a: 1\n---\nb: 2\n")[0].0, "yaml_multi_document");
        assert_eq!(codes("1: a\n")[0], ("yaml_non_string_key", 1, 1));
        assert!(parse("t.yaml", "\"1\": a\n").is_ok());
    }

    #[test]
    fn reports_syntax_errors_with_a_position() {
        let d = parse("t.yaml", "a: [1, 2\nb: 3\n").unwrap_err();
        assert_eq!(d[0].code, "yaml_syntax");
        assert!(d[0].position.line >= 1);
    }

    #[test]
    fn enforces_limits() {
        assert_eq!(codes(&"x".repeat(MAX_BYTES + 1))[0].0, "yaml_too_large");
        let deep = format!("{}1{}", "[".repeat(20), "]".repeat(20));
        assert_eq!(codes(&deep)[0].0, "yaml_too_deep");
        let many = format!("[{}]", vec!["1"; MAX_ITEMS + 1].join(","));
        assert_eq!(codes(&many)[0].0, "yaml_too_many_items");
        assert_eq!(codes("a: 99999999999999999999\n")[0].0, "yaml_int_range");
        assert_eq!(codes("")[0].0, "yaml_empty");
    }

    #[test]
    fn display_has_file_line_column_and_help() {
        let d = &parse("entities/note.yaml", "a: 1\na: 2\n").unwrap_err()[0];
        assert_eq!(
            d.to_string(),
            "entities/note.yaml:2:1: error[yaml_duplicate_key]: duplicate key `a`\n  help: remove one of them or rename it"
        );
    }
}

#[cfg(test)]
mod example_tests {
    use super::*;

    #[test]
    fn the_minimal_example_files_parse() {
        for (name, src) in [
            (
                "app.yaml",
                include_str!("../../../specifications/examples/minimal/app.yaml"),
            ),
            (
                "entities/note.yaml",
                include_str!("../../../specifications/examples/minimal/entities/note.yaml"),
            ),
            (
                "policies/note.yaml",
                include_str!("../../../specifications/examples/minimal/policies/note.yaml"),
            ),
            (
                "commands/archive_note.yaml",
                include_str!("../../../specifications/examples/minimal/commands/archive_note.yaml"),
            ),
        ] {
            let n = parse(name, src).unwrap_or_else(|d| panic!("{name}: {d:?}"));
            assert_eq!(n.get("schema_version").unwrap().value, Value::Int(1));
        }
    }
}
