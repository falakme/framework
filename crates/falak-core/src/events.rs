//! Reads and checks `events/*.yaml` and `workflows/*.yaml` (SCHEMA §9, FEDERATION §13).

use std::collections::HashSet;

use falak_contracts::ir::{IrEventOn, IrSagaStep, Tenancy};

use crate::{
    diagnostics::Diagnostic,
    load::check_version,
    reader::{Ctx, MapReader, is_app_name, is_name, read_list, read_name, read_str, read_u32},
    schema::{Command, CommandKind, Entity, Publish, Saga, Subscribe},
    yaml::{Node, Value},
};

/// The most steps a saga may have.
pub const MAX_SAGA_STEPS: usize = 20;

fn read_app_name(ctx: &mut Ctx, node: &Node, what: &str) -> Option<String> {
    let s = read_str(ctx, node, what)?;
    if is_app_name(s) {
        Some(s.to_owned())
    } else {
        ctx.error(
            "invalid_name",
            node.position,
            format!("{what} `{s}` is not a valid app name"),
        );
        None
    }
}

/// What one event file declares.
pub enum EventFile {
    Publish(Publish),
    Subscribe(Subscribe),
}

pub fn read_event(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<EventFile> {
    let mut m = MapReader::new(
        ctx,
        node,
        "an event file",
        &["schema_version", "event", "publish", "consume"],
    )?;
    check_version(ctx, &mut m);
    let name_node = m.require(ctx, "event");
    let name = name_node.and_then(|n| read_name(ctx, n, "event"));
    if let (Some(c), Some(n)) = (&name, name_node)
        && c != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("event `{c}` must be defined in `events/{c}.yaml`"),
            format!("rename the file or change `event` to `{stem}`"),
        );
    }
    let publish = m.take("publish");
    let consume = m.take("consume");
    m.finish(ctx);
    let name = name?;
    match (publish, consume) {
        (Some(p), None) => read_publish(ctx, p, name).map(EventFile::Publish),
        (None, Some(c)) => read_consume(ctx, c, name).map(EventFile::Subscribe),
        _ => {
            ctx.error_help(
                "invalid_event",
                node.position,
                "an event file has either `publish:` or `consume:`, not both or neither",
                "add one of them",
            );
            None
        }
    }
}

fn read_publish(ctx: &mut Ctx, node: &Node, name: String) -> Option<Publish> {
    let mut m = MapReader::new(
        ctx,
        node,
        "publish",
        &["entity", "on", "version", "fields", "subscribers"],
    )?;
    let entity = m
        .require(ctx, "entity")
        .and_then(|n| read_name(ctx, n, "entity"));
    let on = m
        .require(ctx, "on")
        .and_then(|n| match read_str(ctx, n, "on")? {
            "create" => Some(IrEventOn::Create),
            "update" => Some(IrEventOn::Update),
            "delete" => Some(IrEventOn::Delete),
            other => {
                ctx.error_help(
                    "invalid_value",
                    n.position,
                    format!("`{other}` is not an event trigger"),
                    "use `create`, `update` or `delete`",
                );
                None
            }
        });
    let version = m
        .require(ctx, "version")
        .and_then(|n| read_u32(ctx, n, "version", 1, 10_000));
    let fields = m
        .take("fields")
        .map(|n| read_list(ctx, n, "fields", |c, n| read_name(c, n, "field")))
        .unwrap_or_default();
    let sub_node = m.require(ctx, "subscribers");
    let subscribers = sub_node
        .map(|n| {
            read_list(ctx, n, "subscribers", |c, n| {
                read_app_name(c, n, "subscriber")
            })
        })
        .unwrap_or_default();
    if let Some(n) = sub_node
        && subscribers.is_empty()
    {
        ctx.error_help(
            "missing_subscribers",
            n.position,
            "an event must name the apps allowed to receive it",
            "list them under `subscribers:`",
        );
    }
    m.finish(ctx);
    Some(Publish {
        name,
        entity: entity?,
        on: on?,
        version: version?,
        fields,
        subscribers,
        position: node.position,
    })
}

fn read_consume(ctx: &mut Ctx, node: &Node, event: String) -> Option<Subscribe> {
    let mut m = MapReader::new(ctx, node, "consume", &["from", "version", "handler"])?;
    let from = m
        .require(ctx, "from")
        .and_then(|n| read_app_name(ctx, n, "from"));
    let version = m
        .require(ctx, "version")
        .and_then(|n| read_u32(ctx, n, "version", 1, 10_000));
    let handler = m
        .require(ctx, "handler")
        .and_then(|n| read_name(ctx, n, "handler"));
    m.finish(ctx);
    Some(Subscribe {
        event,
        from: from?,
        version: version?,
        handler: handler?,
        position: node.position,
    })
}

fn read_target(ctx: &mut Ctx, node: &Node, what: &str) -> Option<String> {
    let s = read_str(ctx, node, what)?;
    match s.split_once('.') {
        Some((app, ev)) if is_app_name(app) && is_name(ev) => Some(s.to_owned()),
        _ => {
            ctx.error_help(
                "invalid_name",
                node.position,
                format!("{what} `{s}` is not `<app>.<event>`"),
                "write the app and the event it consumes, for example `inventory.reserve_stock`",
            );
            None
        }
    }
}

pub fn read_saga(ctx: &mut Ctx, node: &Node, stem: &str) -> Option<Saga> {
    let mut m = MapReader::new(
        ctx,
        node,
        "a workflow file",
        &["schema_version", "saga", "start", "steps"],
    )?;
    check_version(ctx, &mut m);
    let name_node = m.require(ctx, "saga");
    let name = name_node.and_then(|n| read_name(ctx, n, "saga"));
    if let (Some(c), Some(n)) = (&name, name_node)
        && c != stem
    {
        ctx.error_help(
            "name_mismatch",
            n.position,
            format!("saga `{c}` must be defined in `workflows/{c}.yaml`"),
            format!("rename the file or change `saga` to `{stem}`"),
        );
    }
    let start = m
        .require(ctx, "start")
        .and_then(|n| read_name(ctx, n, "start"));
    let mut steps: Vec<IrSagaStep> = Vec::new();
    if let Some(n) = m.require(ctx, "steps") {
        match &n.value {
            Value::Seq(items) if !items.is_empty() => {
                if items.len() > MAX_SAGA_STEPS {
                    ctx.error(
                        "too_many_steps",
                        n.position,
                        format!("a saga may have at most {MAX_SAGA_STEPS} steps"),
                    );
                }
                for item in items {
                    let Some(mut sm) =
                        MapReader::new(ctx, item, "a step", &["name", "command", "compensate"])
                    else {
                        continue;
                    };
                    let sname = sm
                        .require(ctx, "name")
                        .and_then(|n| read_name(ctx, n, "name"));
                    let command = sm
                        .require(ctx, "command")
                        .and_then(|n| read_target(ctx, n, "command"));
                    let compensate = sm
                        .take("compensate")
                        .and_then(|n| read_target(ctx, n, "compensate"));
                    sm.finish(ctx);
                    if let (Some(name), Some(command)) = (sname, command) {
                        if steps.iter().any(|s| s.name == name) {
                            ctx.error(
                                "duplicate_step",
                                item.position,
                                format!("step `{name}` is defined twice"),
                            );
                        }
                        steps.push(IrSagaStep {
                            name,
                            command,
                            compensate,
                        });
                    }
                }
            }
            _ => ctx.error(
                "wrong_type",
                n.position,
                "`steps` must be a list with at least one step",
            ),
        }
    }
    m.finish(ctx);
    Some(Saga {
        name: name?,
        start: start?,
        steps,
        position: node.position,
    })
}

#[allow(clippy::too_many_arguments)]
/// Cross-file checks. `entities` and `commands` are the app's, with their file paths.
pub fn validate(
    diags: &mut Vec<Diagnostic>,
    app_name: &str,
    tenancy: Tenancy,
    entities: &[(String, Entity)],
    commands: &[(String, Command)],
    publishes: &[(String, Publish)],
    subscribes: &[(String, Subscribe)],
    sagas: &[(String, Saga)],
) {
    let mut seen = HashSet::new();
    if tenancy == Tenancy::Database
        && let Some((path, p)) = publishes
            .first()
            .map(|(p, x)| (p, x.position))
            .or_else(|| subscribes.first().map(|(p, x)| (p, x.position)))
    {
        Ctx { file: path, diags }.error(
            "unsupported_tenancy",
            p,
            "events are not available with `tenancy: database` in this version",
        );
    }
    for (path, s) in subscribes {
        if tenancy == Tenancy::Row {
            Ctx { file: path, diags }.error_help(
                "unsupported_tenancy",
                s.position,
                "an app with row tenancy cannot consume events: an event carries no tenant",
                "consume from an app with `tenancy: none`, or publish a tenant-neutral event",
            );
        }
    }
    for (path, p) in publishes {
        let mut ctx = Ctx { file: path, diags };
        seen.insert(p.name.clone());
        let Some((_, e)) = entities.iter().find(|(_, e)| e.name == p.entity) else {
            ctx.error(
                "unknown_entity",
                p.position,
                format!("event `{}` refers to unknown entity `{}`", p.name, p.entity),
            );
            continue;
        };
        for f in &p.fields {
            match e.field(f) {
                None => ctx.error(
                    "unknown_field",
                    p.position,
                    format!(
                        "event `{}` lists `{f}`, which `{}` does not declare",
                        p.name, e.name
                    ),
                ),
                Some(field) if field.encrypted => ctx.error(
                    "invalid_event_field",
                    p.position,
                    format!("event `{}` cannot carry the encrypted field `{f}`", p.name),
                ),
                Some(_) => {}
            }
        }
        if p.on == IrEventOn::Delete && !e.lifecycle.soft_delete {
            ctx.error_help(
                "invalid_event",
                p.position,
                format!(
                    "event `{}` fires on delete, but `{}` is not soft delete",
                    p.name, e.name
                ),
                "set `lifecycle: { soft_delete: true }` on the entity",
            );
        }
        if p.subscribers.iter().any(|s| s == app_name) {
            ctx.error(
                "invalid_event",
                p.position,
                format!("event `{}` lists the app itself as a subscriber", p.name),
            );
        }
    }
    let mut keys = HashSet::new();
    for (path, s) in subscribes {
        let mut ctx = Ctx { file: path, diags };
        if s.from == app_name {
            ctx.error(
                "invalid_event",
                s.position,
                format!("event `{}` is consumed from the app itself", s.event),
            );
        }
        if !keys.insert((s.from.clone(), s.event.clone())) {
            ctx.error(
                "duplicate_event",
                s.position,
                format!("event `{}` from `{}` is consumed twice", s.event, s.from),
            );
        }
        match commands.iter().find(|(_, c)| c.name == s.handler) {
            None => ctx.error(
                "unknown_command",
                s.position,
                format!("handler `{}` is not a command of this app", s.handler),
            ),
            Some((_, c)) if c.kind != CommandKind::Create => ctx.error_help(
                "invalid_handler",
                s.position,
                format!("handler `{}` must be a `create` command", s.handler),
                "an event is recorded as a new row",
            ),
            Some(_) => {}
        }
    }
    for (path, s) in sagas {
        let mut ctx = Ctx { file: path, diags };
        if !seen.contains(&s.start) {
            ctx.error_help(
                "unknown_event",
                s.position,
                format!(
                    "saga `{}` starts on `{}`, which this app does not publish",
                    s.name, s.start
                ),
                "name an event under `events/` with `publish:`",
            );
        }
        if s.steps.is_empty() {
            ctx.error("missing_key", s.position, "a saga needs at least one step");
        }
    }
}
