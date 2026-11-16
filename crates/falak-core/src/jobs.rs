//! Job contracts (T7.1): `jobs/<name>.yaml` declares a heavy-compute job, the input it
//! accepts and the limits its container runs under. See ARCHITECTURE §4.9.
//!
//! ```yaml
//! schema_version: 1
//! job: scan_document
//! input: { document_id: { type: uuid } }
//! image: registry.example.com/scan@sha256:...
//! command: [python, main.py]
//! timeout_seconds: 600
//! egress: [api.example.com]
//! ```

use falak_contracts::ir::{FieldType, IrInput, IrJob};

use crate::{
    load::parse_type,
    reader::{Ctx, MapReader, read_list, read_name, read_str, read_u32},
    yaml::{Node, Value},
};

const KEYS: &[&str] = &[
    "schema_version",
    "job",
    "input",
    "image",
    "command",
    "timeout_seconds",
    "max_attempts",
    "memory_mb",
    "cpus",
    "egress",
    "requirements_sha256",
];

fn read_input(ctx: &mut Ctx, node: &Node) -> Vec<IrInput> {
    let mut input = Vec::new();
    let Some(pm) = MapReader::new(ctx, node, "input", &[]) else {
        return input;
    };
    for e in pm.entries() {
        if !crate::reader::is_name(&e.key) {
            ctx.error(
                "invalid_name",
                e.key_position,
                format!("input name `{}` is not valid", e.key),
            );
            continue;
        }
        let Some(mut fm) = MapReader::new(
            ctx,
            &e.value,
            &format!("input `{}`", e.key),
            &["type", "max_length", "required"],
        ) else {
            continue;
        };
        let ty = fm.require(ctx, "type").and_then(|n| parse_type(ctx, n));
        let max_length = fm
            .take("max_length")
            .and_then(|n| read_u32(ctx, n, "max_length", 1, 16_777_216));
        let required = !matches!(
            fm.take("required").map(|n| &n.value),
            Some(Value::Bool(false))
        );
        fm.finish(ctx);
        let Some(ty) = ty else { continue };
        if matches!(ty, FieldType::Bytes) {
            ctx.error(
                "invalid_param_type",
                e.value.position,
                "a job input cannot be bytes; pass an object key instead",
            );
            continue;
        }
        input.push(IrInput {
            name: e.key.clone(),
            ty,
            required,
            max_length,
        });
    }
    input
}

pub fn read_job(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<IrJob> {
    let mut m = MapReader::new(ctx, node, "a job file", KEYS)?;
    match m.require(ctx, "schema_version").map(|n| &n.value) {
        Some(Value::Int(1)) | None => {}
        Some(_) => ctx.error(
            "unsupported_schema_version",
            node.position,
            "schema_version must be 1",
        ),
    }
    let name_node = m.require(ctx, "job");
    let name = name_node.and_then(|n| read_name(ctx, n, "job"));
    if let (Some(c), Some(n)) = (&name, name_node)
        && c != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("job `{c}` must be defined in `jobs/{c}.yaml`"),
            format!("rename the file or change `job` to `{stem}`"),
        );
    }
    let input = m
        .take("input")
        .map(|n| read_input(ctx, n))
        .unwrap_or_default();
    let image = m.require(ctx, "image").and_then(|n| {
        let s = read_str(ctx, n, "image")?;
        if s.is_empty() || s.contains(char::is_whitespace) {
            ctx.error("invalid_image", n.position, "image must be one reference");
            return None;
        }
        Some(s.to_owned())
    });
    let command: Vec<String> = m
        .require(ctx, "command")
        .map(|n| {
            read_list(ctx, n, "command", |ctx, i| {
                read_str(ctx, i, "command argument").map(str::to_owned)
            })
        })
        .unwrap_or_default();
    let timeout_seconds = m
        .take("timeout_seconds")
        .and_then(|n| read_u32(ctx, n, "timeout_seconds", 1, 86_400))
        .unwrap_or(600);
    let max_attempts = m
        .take("max_attempts")
        .and_then(|n| read_u32(ctx, n, "max_attempts", 1, 20))
        .unwrap_or(3);
    let memory_mb = m
        .take("memory_mb")
        .and_then(|n| read_u32(ctx, n, "memory_mb", 16, 131_072))
        .unwrap_or(512);
    let cpus = m
        .take("cpus")
        .and_then(|n| read_u32(ctx, n, "cpus", 1, 64))
        .unwrap_or(1);
    let egress = m
        .take("egress")
        .map(|n| {
            read_list(ctx, n, "egress", |ctx, i| {
                let host = read_str(ctx, i, "egress host")?;
                if host.is_empty() || host.contains(['/', ' ', ':']) {
                    ctx.error_help(
                        "invalid_egress",
                        i.position,
                        format!("`{host}` is not a host name"),
                        "list bare host names such as `api.example.com` or `*.example.com`",
                    );
                    return None;
                }
                Some(host.to_owned())
            })
        })
        .unwrap_or_default();
    let requirements_sha256 = m.take("requirements_sha256").and_then(|n| {
        let s = read_str(ctx, n, "requirements_sha256")?;
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Some(s.to_owned())
        } else {
            ctx.error(
                "invalid_hash",
                n.position,
                "requirements_sha256 must be 64 lowercase hex characters",
            );
            None
        }
    });
    m.finish(ctx);
    if command.is_empty() {
        ctx.error(
            "empty_command",
            node.position,
            "a job needs a non-empty `command`",
        );
    }
    Some(IrJob {
        name: name?,
        input,
        image: image?,
        command,
        timeout_seconds,
        max_attempts,
        memory_mb,
        cpus,
        egress,
        requirements_sha256,
    })
}

/// Check a payload against a job's input contract. Every problem is returned.
pub fn validate_payload(job: &IrJob, payload: &serde_json::Value) -> Result<(), Vec<String>> {
    use serde_json::Value as J;
    let Some(obj) = payload.as_object() else {
        return Err(vec!["the payload must be a JSON object".into()]);
    };
    let mut problems = Vec::new();
    for key in obj.keys() {
        if !job.input.iter().any(|i| &i.name == key) {
            problems.push(format!("unknown input `{key}`"));
        }
    }
    for i in &job.input {
        let Some(v) = obj.get(&i.name).filter(|v| !v.is_null()) else {
            if i.required {
                problems.push(format!("input `{}` is required", i.name));
            }
            continue;
        };
        let ok = match (&i.ty, v) {
            (FieldType::Int64 | FieldType::DecimalMinor, J::Number(n)) => n.is_i64(),
            (FieldType::Bool, J::Bool(_)) | (FieldType::Json, _) => true,
            (FieldType::Text | FieldType::Uuid | FieldType::Timestamptz, J::String(s)) => {
                i.max_length.is_none_or(|m| s.chars().count() <= m as usize)
                    && (i.ty != FieldType::Uuid || crate::values::parse_uuid(s).is_some())
            }
            _ => false,
        };
        if !ok {
            problems.push(format!("input `{}` is not a valid {:?}", i.name, i.ty));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}
