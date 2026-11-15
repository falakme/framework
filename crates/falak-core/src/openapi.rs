//! OpenAPI 3.1 document generated from the IR (T1.11).
//!
//! The document describes the routes the runtimes serve: collection and item routes
//! for each entity and a route per command. An operation appears only when a policy
//! rule grants its action, so the document never advertises a route that default deny
//! would refuse. Output depends only on the IR, so it is stable.

use falak_contracts::ir::{FieldType, Ir, IrAction, IrCommand, IrCommandKind, IrEntity, IrField};
use serde_json::{Map, Value, json};

const OPENAPI_VERSION: &str = "3.1.0";

/// Build the OpenAPI document for an app.
pub fn generate(ir: &Ir) -> Value {
    let mut paths = Map::new();
    let mut schemas = Map::new();
    schemas.insert("Problem".into(), problem_schema());

    for entity in &ir.entities {
        let name = schema_name(&entity.name);
        schemas.insert(name.clone(), entity_schema(entity));
        schemas.insert(format!("{name}Create"), create_schema(entity));
        schemas.insert(format!("{name}Update"), update_schema(entity));
        schemas.insert(format!("{name}List"), list_schema(&name));

        let collection = collection_item(entity, &name);
        if !collection.is_empty() {
            paths.insert(format!("/v1/{}", entity.table), Value::Object(collection));
        }
        let item = item_item(entity, &name);
        if !item.is_empty() {
            paths.insert(format!("/v1/{}/{{id}}", entity.table), Value::Object(item));
        }
    }

    for command in &ir.commands {
        let Some(entity) = ir.entity(&command.entity) else {
            continue;
        };
        if !allowed(entity, command_action(command)) {
            continue;
        }
        let path = format!("/v1/{}/{{id}}/{}", entity.table, command.name);
        paths.insert(path, command_path(entity, command));
    }

    json!({
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": ir.app.name,
            "version": ir.app.version,
            "x-falak-ir-hash": format!("sha256:{}", ir.content_hash),
        },
        "servers": [{ "url": "/" }],
        "security": [{ "bearerAuth": [] }],
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" }
            },
            "parameters": common_parameters(),
            "responses": common_responses(),
            "schemas": Value::Object(schemas),
        },
    })
}

// ---------------------------------------------------------------- naming

/// `release_note` becomes `ReleaseNote`.
fn schema_name(entity: &str) -> String {
    entity
        .split('_')
        .map(|part| {
            let mut c = part.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

fn schema_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn param_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/parameters/{name}") })
}

fn response_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/responses/{name}") })
}

// ---------------------------------------------------------------- policy

fn allowed(entity: &IrEntity, action: IrAction) -> bool {
    entity
        .policy
        .rules
        .iter()
        .any(|r| r.actions.contains(&action))
}

fn command_action(command: &IrCommand) -> IrAction {
    match command.kind {
        IrCommandKind::Create => IrAction::Create,
        IrCommandKind::Delete => IrAction::Delete,
        IrCommandKind::Update | IrCommandKind::Custom => IrAction::Update,
    }
}

// ---------------------------------------------------------------- schemas

fn field_schema(field: &IrField) -> Value {
    let mut s = Map::new();
    let ty = match field.ty {
        FieldType::Uuid => {
            s.insert("format".into(), json!("uuid"));
            Some("string")
        }
        FieldType::Int64 => {
            s.insert("format".into(), json!("int64"));
            Some("integer")
        }
        FieldType::DecimalMinor => {
            s.insert("format".into(), json!("int64"));
            s.insert(
                "description".into(),
                json!("An integer count of minor currency units. Never a decimal."),
            );
            Some("integer")
        }
        FieldType::Text => Some("string"),
        FieldType::Bool => Some("boolean"),
        FieldType::Timestamptz => {
            s.insert("format".into(), json!("date-time"));
            Some("string")
        }
        FieldType::Bytes => {
            s.insert("contentEncoding".into(), json!("base64"));
            Some("string")
        }
        FieldType::Json => None,
    };
    if let Some(ty) = ty {
        if field.nullable && !field.builtin {
            s.insert("type".into(), json!([ty, "null"]));
        } else {
            s.insert("type".into(), json!(ty));
        }
    }
    if let Some(max) = field.max_length
        && matches!(field.ty, FieldType::Text)
    {
        s.insert("maxLength".into(), json!(max));
    }
    if let Some(min) = field.min {
        s.insert("minimum".into(), json!(min));
    }
    if let Some(max) = field.max {
        s.insert("maximum".into(), json!(max));
    }
    if field.pii {
        s.insert("x-falak-pii".into(), json!(true));
    }
    Value::Object(s)
}

/// Fields a caller may set: declared by the app, not the owner field and not computed.
pub(crate) fn writable(entity: &IrEntity) -> impl Iterator<Item = &IrField> {
    entity
        .fields
        .iter()
        .filter(|f| !f.builtin && entity.owner.as_deref() != Some(f.name.as_str()))
}

fn entity_schema(entity: &IrEntity) -> Value {
    let mut props = Map::new();
    let mut required = Vec::new();
    for f in &entity.fields {
        props.insert(f.name.clone(), field_schema(f));
        if !f.nullable {
            required.push(json!(f.name));
        }
    }
    json!({
        "type": "object",
        "properties": Value::Object(props),
        "required": required,
        "additionalProperties": false,
    })
}

fn create_schema(entity: &IrEntity) -> Value {
    let mut props = Map::new();
    let mut required = Vec::new();
    for f in writable(entity) {
        props.insert(f.name.clone(), field_schema(f));
        if !f.nullable && f.default.is_none() {
            required.push(json!(f.name));
        }
    }
    json!({
        "type": "object",
        "description": "The owner and the built-in fields are set by the server and are rejected if sent.",
        "properties": Value::Object(props),
        "required": required,
        "additionalProperties": false,
    })
}

fn update_schema(entity: &IrEntity) -> Value {
    let mut props = Map::new();
    for f in writable(entity) {
        props.insert(f.name.clone(), field_schema(f));
    }
    json!({
        "type": "object",
        "description": "Send only the fields to change. Send If-Match with the current ETag.",
        "properties": Value::Object(props),
        "additionalProperties": false,
    })
}

fn list_schema(name: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "data": { "type": "array", "items": schema_ref(name) },
            "meta": {
                "type": "object",
                "properties": {
                    "page_size": { "type": "integer" },
                    "has_more": { "type": "boolean" },
                    "next_cursor": { "type": ["string", "null"] },
                    "prev_cursor": { "type": ["string", "null"] },
                },
                "required": ["page_size", "has_more", "next_cursor", "prev_cursor"],
            },
        },
        "required": ["data", "meta"],
    })
}

fn problem_schema() -> Value {
    json!({
        "type": "object",
        "description": "RFC 9457 problem details.",
        "properties": {
            "type": { "type": "string" },
            "title": { "type": "string" },
            "status": { "type": "integer" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
            "instance": { "type": "string" },
            "request_id": { "type": "string" },
            "invalid_params": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "reason": { "type": "string" },
                        "code": { "type": "string" },
                    },
                    "required": ["name", "reason", "code"],
                },
            },
        },
        "required": ["type", "title", "status", "code"],
    })
}

// ---------------------------------------------------------------- shared parts

fn common_parameters() -> Value {
    json!({
        "Id": { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } },
        "IfMatch": { "name": "If-Match", "in": "header", "required": false,
            "description": "The ETag from the last read. A stale value returns 412.",
            "schema": { "type": "string" } },
        "IdempotencyKey": { "name": "Idempotency-Key", "in": "header", "required": false,
            "description": "A unique key. A repeat with the same body returns the first result.",
            "schema": { "type": "string", "maxLength": 255 } },
        "PageSize": { "name": "page[size]", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 } },
        "PageAfter": { "name": "page[after]", "in": "query", "schema": { "type": "string" } },
        "PageBefore": { "name": "page[before]", "in": "query", "schema": { "type": "string" } },
        "Sort": { "name": "sort", "in": "query",
            "description": "Comma-separated field names. Prefix a name with `-` for descending.",
            "schema": { "type": "string" } },
        "Filter": { "name": "filter", "in": "query", "style": "deepObject", "explode": true,
            "description": "`filter[field]=value` or `filter[field][op]=value`. Operators: eq, neq, gt, gte, lt, lte, in, like, is_null. At most 10 predicates.",
            "schema": { "type": "object", "additionalProperties": true } },
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/problem+json": { "schema": schema_ref("Problem") } },
    })
}

fn common_responses() -> Value {
    json!({
        "BadRequest": problem_response("The request is malformed or fails validation."),
        "Unauthorized": problem_response("No valid bearer token."),
        "NotFound": problem_response("Not found, or not visible to the caller."),
        "Conflict": problem_response("The request conflicts with current state."),
        "PreconditionFailed": problem_response("The If-Match version is stale."),
        "TooManyRequests": problem_response("Rate limit exceeded."),
    })
}

fn error_responses(with_precondition: bool) -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("400".into(), response_ref("BadRequest"));
    r.insert("401".into(), response_ref("Unauthorized"));
    r.insert("404".into(), response_ref("NotFound"));
    r.insert("409".into(), response_ref("Conflict"));
    if with_precondition {
        r.insert("412".into(), response_ref("PreconditionFailed"));
    }
    r.insert("429".into(), response_ref("TooManyRequests"));
    r
}

fn json_body(schema: Value) -> Value {
    json!({ "required": true, "content": { "application/json": { "schema": schema } } })
}

fn json_ok(description: &str, schema: Value, etag: bool) -> Value {
    let mut r = json!({
        "description": description,
        "content": { "application/json": { "schema": schema } },
    });
    if etag {
        r["headers"] = json!({ "ETag": { "schema": { "type": "string" } } });
    }
    r
}

// ---------------------------------------------------------------- operations

fn collection_item(entity: &IrEntity, name: &str) -> Map<String, Value> {
    let mut item = Map::new();
    let tag = entity.name.clone();
    if allowed(entity, IrAction::Read) {
        let mut responses = error_responses(false);
        responses.insert(
            "200".into(),
            json_ok(
                "A page of records.",
                schema_ref(&format!("{name}List")),
                false,
            ),
        );
        item.insert(
            "get".into(),
            json!({
                "operationId": format!("list_{}", entity.table),
                "summary": format!("List {}", entity.table),
                "tags": [tag],
                "parameters": [
                    param_ref("PageSize"), param_ref("PageAfter"), param_ref("PageBefore"),
                    param_ref("Sort"), param_ref("Filter"),
                ],
                "responses": Value::Object(responses),
            }),
        );
    }
    if allowed(entity, IrAction::Create) {
        let mut responses = error_responses(false);
        responses.insert(
            "201".into(),
            json_ok("The created record.", schema_ref(name), true),
        );
        item.insert(
            "post".into(),
            json!({
                "operationId": format!("create_{}", entity.name),
                "summary": format!("Create a {}", entity.name),
                "tags": [tag],
                "parameters": [param_ref("IdempotencyKey")],
                "requestBody": json_body(schema_ref(&format!("{name}Create"))),
                "responses": Value::Object(responses),
            }),
        );
    }
    item
}

fn item_item(entity: &IrEntity, name: &str) -> Map<String, Value> {
    let mut item = Map::new();
    let tag = entity.name.clone();
    if allowed(entity, IrAction::Read) {
        let mut responses = error_responses(false);
        responses.insert("200".into(), json_ok("The record.", schema_ref(name), true));
        item.insert(
            "get".into(),
            json!({
                "operationId": format!("get_{}", entity.name),
                "summary": format!("Get a {}", entity.name),
                "tags": [tag],
                "parameters": [param_ref("Id")],
                "responses": Value::Object(responses),
            }),
        );
    }
    if allowed(entity, IrAction::Update) {
        let mut responses = error_responses(true);
        responses.insert(
            "200".into(),
            json_ok("The updated record.", schema_ref(name), true),
        );
        item.insert(
            "patch".into(),
            json!({
                "operationId": format!("update_{}", entity.name),
                "summary": format!("Update a {}", entity.name),
                "tags": [tag],
                "parameters": [param_ref("Id"), param_ref("IfMatch"), param_ref("IdempotencyKey")],
                "requestBody": json_body(schema_ref(&format!("{name}Update"))),
                "responses": Value::Object(responses),
            }),
        );
    }
    if allowed(entity, IrAction::Delete) {
        let mut responses = error_responses(true);
        responses.insert("204".into(), json!({ "description": "Deleted." }));
        item.insert(
            "delete".into(),
            json!({
                "operationId": format!("delete_{}", entity.name),
                "summary": format!("Delete a {}", entity.name),
                "tags": [tag],
                "parameters": [param_ref("Id"), param_ref("IfMatch")],
                "responses": Value::Object(responses),
            }),
        );
    }
    item
}

fn command_path(entity: &IrEntity, command: &IrCommand) -> Value {
    let name = schema_name(&entity.name);
    // The target id travels in the path, not the body.
    let mut props = Map::new();
    let mut required = Vec::new();
    for input in command
        .input
        .iter()
        .filter(|i| Some(&i.name) != command.target.as_ref())
    {
        let field = IrField {
            name: input.name.clone(),
            ty: input.ty.clone(),
            nullable: !input.required,
            unique: false,
            indexed: false,
            pii: false,
            encrypted: false,
            max_length: input.max_length,
            min: None,
            max: None,
            default: None,
            references: None,
            builtin: false,
        };
        props.insert(input.name.clone(), field_schema(&field));
        if input.required {
            required.push(json!(input.name));
        }
    }
    let mut responses = error_responses(true);
    responses.insert(
        "200".into(),
        json_ok("The record after the command.", schema_ref(&name), true),
    );
    let mut parameters = vec![param_ref("Id"), param_ref("IfMatch")];
    if command.idempotent {
        parameters.push(param_ref("IdempotencyKey"));
    }
    json!({
        "post": {
            "operationId": command.name,
            "summary": format!("Run `{}` on a {}", command.name, entity.name),
            "tags": [entity.name],
            "parameters": parameters,
            "requestBody": json_body(json!({
                "type": "object",
                "properties": Value::Object(props),
                "required": required,
                "additionalProperties": false,
            })),
            "responses": Value::Object(responses),
        }
    })
}
