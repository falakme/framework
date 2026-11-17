//! Request handlers for entity CRUD and commands.

use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use falak_contracts::{
    Error, ErrorKind,
    driver::Value,
    identity::{Principal, RequestContext},
    ir::{IrAction, IrCommandKind, IrEntity, IrEventOn, IrSetValue},
};
use falak_core::{
    command::{self, Plan},
    policy::{Access, authorize},
    sql::{
        self, Condition, Dialect, Filter, ListQuery, Op, Request, Scope, SortKey, WriteContext,
        cursor_from_row, denial_for,
    },
    values::{format_uuid, parse_uuid},
};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{
    app::AppState,
    context::{extract_request_id, make_context, make_scope},
    driver::NativeDriver,
    error::problem_response,
    idempotency::{CachedResponse, CheckResult, IdempotencyKeyScope},
    json::{json_to_driver_value, row_to_json_object},
};

/// `GET /v1/_schema`: what this caller can manage in the app, for generic tools such as
/// Studio. Only entities the caller may read are listed, with the actions they may take
/// and the presentation metadata from `admin:`. The caller's own policy decides: nothing
/// here widens access.
pub async fn schema_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    headers: HeaderMap,
) -> Response {
    let req_id = extract_request_id(&headers);
    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), "/v1/_schema", &req_id, vec![]);
    };
    let entities: Vec<serde_json::Value> = state
        .ir
        .entities
        .iter()
        .filter_map(|e| {
            let read = authorize(e, IrAction::Read, Some(&principal));
            if read.is_denied() {
                return None;
            }
            // A field no rule that reaches the caller grants is not listed: its name,
            // type and flags are as private as its values.
            let visible = |name: &str| {
                e.field(name).is_some_and(|f| match &read {
                    Access::Grants(grants) => grants.iter().any(|g| g.allows_field(f)),
                    _ => true,
                })
            };
            let can = |a| !authorize(e, a, Some(&principal)).is_denied();
            Some(serde_json::json!({
                "name": e.name,
                "path": e.table,
                "owner": e.owner.as_ref().filter(|o| visible(o)),
                "can": {
                    "read": true,
                    "create": can(IrAction::Create),
                    "update": can(IrAction::Update),
                    "delete": can(IrAction::Delete),
                },
                "admin": {
                    "label": e.admin.label,
                    "list_columns": e.admin.list_columns.iter().filter(|c| visible(c)).collect::<Vec<_>>(),
                    "search_fields": e.admin.search_fields.iter().filter(|c| visible(c)).collect::<Vec<_>>(),
                },
                "fields": e.fields.iter().filter(|f| visible(&f.name)).map(|f| serde_json::json!({
                    "name": f.name,
                    "type": f.ty,
                    "nullable": f.nullable,
                    "pii": f.pii,
                    "encrypted": f.encrypted,
                    "builtin": f.builtin,
                    "references": f.references.as_ref().map(|(entity, _)| entity),
                })).collect::<Vec<_>>(),
            }))
        })
        .collect();
    build_response(
        StatusCode::OK,
        serde_json::json!({"app": state.ir.app.name, "entities": entities}),
        None,
        &req_id,
        false,
    )
}

fn now_micros() -> i64 {
    use falak_contracts::support::Clock;
    falak_auth::system::SystemClock.now_micros()
}

fn fresh_uuid() -> [u8; 16] {
    use falak_contracts::support::IdGenerator;
    falak_auth::system::RandomIds.new_id()
}

fn dialect_for_driver<D: NativeDriver>(driver: &D) -> Dialect {
    match driver.profile().name {
        "postgres" => Dialect::Postgres,
        "d1" => Dialect::D1,
        _ => Dialect::Sqlite,
    }
}

/// A write changed no rows. With `If-Match` that means either the version moved on or
/// the row is not there for this caller. Say 412 only if the caller can read the row;
/// otherwise 404, so a caller cannot tell a row they may not see from one that does not
/// exist.
#[allow(clippy::too_many_arguments)]
async fn nothing_changed<D: NativeDriver>(
    state: &AppState<D>,
    entity: &IrEntity,
    id: [u8; 16],
    principal: Option<&Principal>,
    scope: &Scope,
    ctx: &RequestContext,
    if_match: Option<i64>,
    instance: &str,
    req_id: &str,
) -> Response {
    let not_found = || problem_response(&Error::not_found(), instance, req_id, vec![]);
    if if_match.is_none() {
        return not_found();
    }
    let access = authorize(entity, IrAction::Read, principal);
    if access.is_denied() {
        return not_found();
    }
    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope,
    };
    let visible = match sql::get(req, id) {
        Ok(Some(stmt)) => state
            .driver
            .query(ctx, stmt)
            .await
            .is_ok_and(|rows| !rows.rows.is_empty()),
        _ => false,
    };
    if visible {
        let err = Error::new(
            ErrorKind::PreconditionFailed,
            "precondition_failed",
            "Precondition failed: resource version mismatch",
        );
        problem_response(&err, instance, req_id, vec![])
    } else {
        not_found()
    }
}

fn parse_if_match(headers: &HeaderMap) -> Option<i64> {
    let header_val = headers.get(header::IF_MATCH)?;
    let s = header_val.to_str().ok()?.trim();
    let clean = s.strip_prefix("W/").unwrap_or(s).trim_matches('"');
    clean.parse().ok()
}

fn parse_cursor(raw: &str) -> Option<Vec<Value>> {
    let bytes = hex::decode(raw).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn encode_cursor(values: &[Value]) -> String {
    let bytes = serde_json::to_vec(values).unwrap_or_default();
    hex::encode(bytes)
}

/// The longest `Idempotency-Key` accepted. Keys are stored for a day, so an unbounded one
/// would be a way to fill the store.
const MAX_IDEMPOTENCY_KEY: usize = 255;

/// The scope an `Idempotency-Key` header makes: the caller, in their tenant, the method,
/// the path and the key (API specification §5.2). The tenant is part of the caller: one
/// subject can hold tokens for more than one tenant, and a key used in one must never
/// replay a response stored in another.
fn idempotency_scope(
    headers: &HeaderMap,
    scope: &Scope,
    method: &str,
    path: &str,
) -> Result<Option<IdempotencyKeyScope>, Error> {
    let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY {
        return Err(Error::invalid_input(
            "invalid_idempotency_key",
            "The Idempotency-Key must be between 1 and 255 characters.",
        ));
    }
    let subject = scope.subject.clone().unwrap_or_default();
    let subject = match scope.tenant.as_deref() {
        Some(tenant) => format!("{tenant}/{subject}"),
        None => subject,
    };
    Ok(Some(IdempotencyKeyScope {
        subject,
        method: method.to_string(),
        path: path.to_string(),
        key: key.to_string(),
    }))
}

fn find_entity<'a>(ir: &'a falak_contracts::ir::Ir, name: &str) -> Option<&'a IrEntity> {
    ir.entities
        .iter()
        .find(|e| e.name == name || e.table == name)
}

fn build_response(
    status: StatusCode,
    body_json: serde_json::Value,
    etag: Option<String>,
    request_id: &str,
    replayed: bool,
) -> Response {
    let mut res = (status, body_json.to_string()).into_response();
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache, no-store, must-revalidate"),
    );
    if let Ok(val) = HeaderValue::from_str(request_id) {
        headers.insert("x-request-id", val);
    }
    if let Some(tag) = etag
        && let Ok(val) = HeaderValue::from_str(&format!("W/\"{tag}\""))
    {
        headers.insert(header::ETAG, val);
    }
    if replayed {
        headers.insert("idempotent-replayed", HeaderValue::from_static("true"));
    }
    res
}

pub async fn list_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path(entity_name): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());
    let access = authorize(entity, IrAction::Read, principal.as_ref());

    let page_size = params
        .get("page[size]")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(sql::DEFAULT_PAGE_SIZE);

    if access.is_denied() {
        let envelope = serde_json::json!({
            "data": [],
            "meta": {
                "page_size": page_size,
                "has_more": false,
                "next_cursor": null,
            }
        });
        return build_response(StatusCode::OK, envelope, None, &req_id, false);
    }

    let mut sort = Vec::new();
    if let Some(sort_str) = params.get("sort") {
        for part in sort_str.split(',') {
            let part = part.trim();
            if let Some(field) = part.strip_prefix('-') {
                sort.push(SortKey {
                    field: field.to_string(),
                    descending: true,
                });
            } else if !part.is_empty() {
                sort.push(SortKey {
                    field: part.to_string(),
                    descending: false,
                });
            }
        }
    }

    let mut filters = Vec::new();
    for (k, v) in &params {
        if let Some(fld) = k.strip_prefix("filter[")
            && let Some(fld) = fld.strip_suffix(']')
        {
            // A filter that cannot be applied is refused, never dropped: dropping it
            // would answer with rows the caller asked to exclude. An unknown field gets
            // the same answer as a field the caller may not read (`sql::list`), so the
            // two cannot be told apart.
            let bad = |m: String| {
                problem_response(
                    &Error::invalid_input("invalid_filter", m),
                    &instance,
                    &req_id,
                    vec![],
                )
            };
            let Some(field) = entity.field(fld) else {
                return bad(format!("cannot filter on unknown field `{fld}`"));
            };
            let v_nfc: String = v.nfc().collect();
            match falak_core::values::coerce_text(field, &v_nfc) {
                Ok(val) => filters.push(Filter {
                    field: fld.to_string(),
                    condition: Condition::Compare(Op::Eq, val),
                }),
                Err(_) => return bad(format!("the value for `{fld}` has the wrong type")),
            }
        }
    }

    let after = match params.get("page[after]") {
        None => None,
        Some(c) => match parse_cursor(c) {
            Some(v) => Some(v),
            None => {
                return problem_response(
                    &Error::invalid_input("invalid_cursor", "The cursor is not valid."),
                    &instance,
                    &req_id,
                    vec![],
                );
            }
        },
    };

    let query = ListQuery {
        filters,
        sort,
        page_size: Some(page_size),
        after,
    };

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let plan_res = sql::list(req, &query);
    let plan = match plan_res {
        Ok(Some(p)) => p,
        Ok(None) => {
            let envelope = serde_json::json!({
                "data": [],
                "meta": {
                    "page_size": page_size,
                    "has_more": false,
                    "next_cursor": null,
                }
            });
            return build_response(StatusCode::OK, envelope, None, &req_id, false);
        }
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let rows_res = state.driver.query(&ctx, plan.statement).await;
    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let has_more = rows.rows.len() > page_size as usize;
    let result_rows = if has_more {
        &rows.rows[..page_size as usize]
    } else {
        &rows.rows[..]
    };

    let next_cursor = if has_more && !result_rows.is_empty() {
        let last_row = &result_rows[result_rows.len() - 1];
        cursor_from_row(&rows.columns, last_row, &plan.sort).map(|vals| encode_cursor(&vals))
    } else {
        None
    };

    let data: Vec<serde_json::Value> = result_rows
        .iter()
        .map(|r| row_to_json_object(Some(entity), &rows.columns, r))
        .collect();

    let envelope = serde_json::json!({
        "data": data,
        "meta": {
            "page_size": page_size,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
    });

    build_response(StatusCode::OK, envelope, None, &req_id, false)
}

pub async fn get_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path((entity_name, id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}/{id_str}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(id_bytes) = parse_uuid(&id_str) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());
    let access = authorize(entity, IrAction::Read, principal.as_ref());

    if access.is_denied() {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    }

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let stmt = match sql::get(req, id_bytes) {
        Ok(Some(s)) => s,
        Ok(None) => return problem_response(&Error::not_found(), &instance, &req_id, vec![]),
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let rows = match state.driver.query(&ctx, stmt).await {
        Ok(r) => r,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    if rows.rows.is_empty() {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    }

    let row = &rows.rows[0];
    let mut version_str = None;
    if let Some(v_idx) = rows.columns.iter().position(|c| c == "version") {
        if let Value::Int64(v) = row[v_idx] {
            version_str = Some(v.to_string());
        }
    }

    let obj = row_to_json_object(Some(entity), &rows.columns, row);
    build_response(StatusCode::OK, obj, version_str, &req_id, false)
}

pub async fn create_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path(entity_name): Path<String>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());

    let payload_hash = hex::encode(Sha256::digest(&body_bytes));
    let idempotency_scope = match idempotency_scope(&headers, &scope, "POST", &instance) {
        Ok(s) => s,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    if let Some(ref iscope) = idempotency_scope {
        match state
            .idempotency
            .check_or_start(iscope, &payload_hash)
            .await
        {
            Ok(CheckResult::Proceed) => {}
            Ok(CheckResult::Replay(cached)) => {
                let json_val =
                    serde_json::from_slice(&cached.body).unwrap_or(serde_json::Value::Null);
                return build_response(cached.status, json_val, cached.etag, &req_id, true);
            }
            Err(e) => return crate::idempotency::rejection(&e, &instance, &req_id),
        }
    }

    let json_body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(
                &Error::invalid_input("invalid_input", "Malformed JSON body"),
                &instance,
                &req_id,
                vec![],
            );
        }
    };

    let Some(map) = json_body.as_object() else {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope).await;
        }
        return problem_response(
            &Error::invalid_input("invalid_input", "JSON body must be an object"),
            &instance,
            &req_id,
            vec![],
        );
    };

    let mut fields = Vec::new();
    for (key, val) in map {
        let Some(f) = entity.field(key) else {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(
                &Error::invalid_input("invalid_field", format!("unknown field `{key}`")),
                &instance,
                &req_id,
                vec![],
            );
        };
        match json_to_driver_value(val, f) {
            Ok(v) => fields.push((key.clone(), v)),
            Err(e) => {
                if let Some(ref iscope) = idempotency_scope {
                    state.idempotency.release(iscope).await;
                }
                return problem_response(&e, &instance, &req_id, vec![]);
            }
        }
    }

    let access = authorize(entity, IrAction::Create, principal.as_ref());
    if access.is_denied() {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope).await;
        }
        return problem_response(&Error::forbidden(), &instance, &req_id, vec![]);
    }

    let write_ctx = WriteContext {
        now_micros: now_micros(),
        new_id: fresh_uuid(),
    };

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let stmt = match sql::insert(req, &fields, &write_ctx) {
        Ok(Some(s)) => s,
        Ok(None) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&Error::forbidden(), &instance, &req_id, vec![]);
        }
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let mut batch = vec![stmt];
    batch.extend(crate::events::outbox_statements(
        &state.ir,
        dialect_for_driver(&*state.driver),
        entity,
        IrEventOn::Create,
        write_ctx.new_id,
        &write_ctx,
        &fields,
    ));
    let outcomes = match state.driver.batch(&ctx, batch).await {
        Ok(o) => o,
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let created_row = outcomes.into_iter().next().map(|o| o.rows);
    let response_json = if let Some(r) = created_row
        && !r.rows.is_empty()
    {
        row_to_json_object(Some(entity), &r.columns, &r.rows[0])
    } else {
        serde_json::json!({
            "id": format_uuid(&write_ctx.new_id),
            "version": 1
        })
    };

    let mut res = build_response(
        StatusCode::CREATED,
        response_json.clone(),
        Some("1".to_string()),
        &req_id,
        false,
    );
    let loc = format!("/v1/{entity_name}/{}", format_uuid(&write_ctx.new_id));
    if let Ok(val) = HeaderValue::from_str(&loc) {
        res.headers_mut().insert(header::LOCATION, val);
    }

    if let Some(iscope) = idempotency_scope {
        state
            .idempotency
            .complete(
                iscope,
                payload_hash,
                CachedResponse {
                    status: StatusCode::CREATED,
                    etag: Some("1".to_string()),
                    body: response_json.to_string().into_bytes(),
                },
            )
            .await;
    }

    res
}

pub async fn update_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path((entity_name, id_str)): Path<(String, String)>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}/{id_str}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(id_bytes) = parse_uuid(&id_str) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());
    let if_match = parse_if_match(&headers);

    let payload_hash = hex::encode(Sha256::digest(&body_bytes));
    let idempotency_scope = match idempotency_scope(&headers, &scope, "PATCH", &instance) {
        Ok(s) => s,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    if let Some(ref iscope) = idempotency_scope {
        match state
            .idempotency
            .check_or_start(iscope, &payload_hash)
            .await
        {
            Ok(CheckResult::Proceed) => {}
            Ok(CheckResult::Replay(cached)) => {
                let json_val =
                    serde_json::from_slice(&cached.body).unwrap_or(serde_json::Value::Null);
                return build_response(cached.status, json_val, cached.etag, &req_id, true);
            }
            Err(e) => return crate::idempotency::rejection(&e, &instance, &req_id),
        }
    }

    let json_body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(
                &Error::invalid_input("invalid_input", "Malformed JSON body"),
                &instance,
                &req_id,
                vec![],
            );
        }
    };

    let Some(map) = json_body.as_object() else {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope).await;
        }
        return problem_response(
            &Error::invalid_input("invalid_input", "JSON body must be an object"),
            &instance,
            &req_id,
            vec![],
        );
    };

    let mut changes = Vec::new();
    for (key, val) in map {
        let Some(f) = entity.field(key) else {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(
                &Error::invalid_input("invalid_field", format!("unknown field `{key}`")),
                &instance,
                &req_id,
                vec![],
            );
        };
        match json_to_driver_value(val, f) {
            Ok(v) => changes.push((key.clone(), v)),
            Err(e) => {
                if let Some(ref iscope) = idempotency_scope {
                    state.idempotency.release(iscope).await;
                }
                return problem_response(&e, &instance, &req_id, vec![]);
            }
        }
    }

    let access = authorize(entity, IrAction::Update, principal.as_ref());
    if access.is_denied() {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope).await;
        }
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    }

    let write_ctx = WriteContext {
        now_micros: now_micros(),
        new_id: fresh_uuid(),
    };

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let stmt = match sql::update(req, id_bytes, &changes, if_match, &write_ctx) {
        Ok(Some(s)) => s,
        Ok(None) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
        }
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let mut batch = vec![stmt];
    batch.extend(crate::events::outbox_statements(
        &state.ir,
        dialect_for_driver(&*state.driver),
        entity,
        IrEventOn::Update,
        id_bytes,
        &write_ctx,
        &changes,
    ));
    let outcomes = match state.driver.batch(&ctx, batch).await {
        Ok(o) => o,
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope).await;
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let outcome = outcomes.into_iter().next().unwrap_or_default();
    if outcome.rows_affected == 0 {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope).await;
        }
        return nothing_changed(
            &state,
            entity,
            id_bytes,
            principal.as_ref(),
            &scope,
            &ctx,
            if_match,
            &instance,
            &req_id,
        )
        .await;
    }

    let updated_json = if !outcome.rows.rows.is_empty() {
        row_to_json_object(Some(entity), &outcome.rows.columns, &outcome.rows.rows[0])
    } else {
        serde_json::json!({"id": id_str, "status": "updated"})
    };

    let new_version = updated_json
        .get("version")
        .and_then(|v| v.as_i64())
        .map(|v| v.to_string());

    let res = build_response(
        StatusCode::OK,
        updated_json.clone(),
        new_version.clone(),
        &req_id,
        false,
    );

    if let Some(iscope) = idempotency_scope {
        state
            .idempotency
            .complete(
                iscope,
                payload_hash,
                CachedResponse {
                    status: StatusCode::OK,
                    etag: new_version,
                    body: updated_json.to_string().into_bytes(),
                },
            )
            .await;
    }

    res
}

pub async fn delete_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path((entity_name, id_str)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}/{id_str}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(id_bytes) = parse_uuid(&id_str) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());
    let if_match = parse_if_match(&headers);

    let access = authorize(entity, IrAction::Delete, principal.as_ref());
    if access.is_denied() {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    }

    let write_ctx = WriteContext {
        now_micros: now_micros(),
        new_id: fresh_uuid(),
    };

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let stmt = match sql::delete(req, id_bytes, if_match, &write_ctx) {
        Ok(Some(s)) => s,
        Ok(None) => return problem_response(&Error::not_found(), &instance, &req_id, vec![]),
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let mut batch = vec![stmt];
    batch.extend(crate::events::outbox_statements(
        &state.ir,
        dialect_for_driver(&*state.driver),
        entity,
        IrEventOn::Delete,
        id_bytes,
        &write_ctx,
        &[],
    ));
    let outcomes = match state.driver.batch(&ctx, batch).await {
        Ok(o) => o,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let outcome = outcomes.into_iter().next().unwrap_or_default();
    if outcome.rows_affected == 0 {
        return nothing_changed(
            &state,
            entity,
            id_bytes,
            principal.as_ref(),
            &scope,
            &ctx,
            if_match,
            &instance,
            &req_id,
        )
        .await;
    }

    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(val) = HeaderValue::from_str(&req_id) {
        res.headers_mut().insert("x-request-id", val);
    }
    res
}

pub async fn command_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path((entity_name, id_str, cmd_name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/{entity_name}/{id_str}/{cmd_name}");

    let Some(entity) = find_entity(&state.ir, &entity_name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    // A command runs only on the entity it is declared for.
    let Some(command) = state
        .ir
        .commands
        .iter()
        .find(|c| c.name == cmd_name && c.entity == entity.name)
    else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(id_bytes) = parse_uuid(&id_str) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };

    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());
    let if_match = parse_if_match(&headers);

    // A command is authorised as the action it performs (AUTHORIZATION §3): an update
    // command needs `update`, a delete command `delete`, a create command `create`.
    let action = match command.kind {
        IrCommandKind::Create => IrAction::Create,
        IrCommandKind::Delete => IrAction::Delete,
        IrCommandKind::Update | IrCommandKind::Custom => IrAction::Update,
    };
    let access = authorize(entity, action, principal.as_ref());
    if access.is_denied() {
        return problem_response(&denial_for(action), &instance, &req_id, vec![]);
    }

    let write_ctx = WriteContext {
        now_micros: now_micros(),
        new_id: fresh_uuid(),
    };

    let req = Request {
        ir: &state.ir,
        entity,
        dialect: dialect_for_driver(&*state.driver),
        access: &access,
        scope: &scope,
    };

    let mut inputs = vec![("id".to_string(), Value::Uuid(id_bytes))];
    if let Ok(json_body) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        && let Some(obj) = json_body.as_object()
    {
        for (k, v) in obj {
            if let Some(inp) = command.input.iter().find(|i| &i.name == k) {
                let fld = falak_contracts::ir::IrField {
                    name: inp.name.clone(),
                    ty: inp.ty.clone(),
                    nullable: !inp.required,
                    unique: false,
                    indexed: false,
                    pii: false,
                    encrypted: false,
                    max_length: inp.max_length,
                    min: None,
                    max: None,
                    default: None,
                    references: None,
                    builtin: false,
                };
                if let Ok(val) = json_to_driver_value(v, &fld) {
                    inputs.push((k.clone(), val));
                }
            }
        }
    }

    let plan = match command::plan(req, command, &inputs, if_match, &write_ctx) {
        Ok(Plan::Run(s)) => s,
        Ok(Plan::Denied) => {
            return problem_response(&denial_for(action), &instance, &req_id, vec![]);
        }
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let on = match command.kind {
        IrCommandKind::Delete => Some(IrEventOn::Delete),
        IrCommandKind::Update => Some(IrEventOn::Update),
        _ => None,
    };
    let mut batch = vec![plan];
    if let Some(on) = on {
        let mut known: Vec<(String, Value)> = inputs.clone();
        for (field, v) in &command.set {
            known.push((
                field.clone(),
                match v {
                    IrSetValue::Bool(b) => Value::Bool(*b),
                    IrSetValue::Int(i) => Value::Int64(*i),
                    IrSetValue::Text(s) => Value::Text(s.clone()),
                    IrSetValue::Now => Value::TimestampMicros(write_ctx.now_micros),
                    IrSetValue::Input(n) => inputs
                        .iter()
                        .find(|(k, _)| k == n)
                        .map_or(Value::Null, |(_, v)| v.clone()),
                },
            ));
        }
        batch.extend(crate::events::outbox_statements(
            &state.ir,
            dialect_for_driver(&*state.driver),
            entity,
            on,
            id_bytes,
            &write_ctx,
            &known,
        ));
    }
    let outcomes = match state.driver.batch(&ctx, batch).await {
        Ok(o) => o,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let outcome = outcomes.into_iter().next().unwrap_or_default();
    if outcome.rows_affected == 0 {
        return nothing_changed(
            &state,
            entity,
            id_bytes,
            principal.as_ref(),
            &scope,
            &ctx,
            if_match,
            &instance,
            &req_id,
        )
        .await;
    }

    let updated_json = if !outcome.rows.rows.is_empty() {
        row_to_json_object(Some(entity), &outcome.rows.columns, &outcome.rows.rows[0])
    } else {
        serde_json::json!({"id": id_str, "status": "ok"})
    };

    let new_version = updated_json
        .get("version")
        .and_then(|v| v.as_i64())
        .map(|v| v.to_string());

    build_response(StatusCode::OK, updated_json, new_version, &req_id, false)
}

/// `GET /v1/_queries/{name}`: run a level 2 query (ARCHITECTURE §4.7). The SQL is fixed
/// in the app; the caller supplies only the declared parameters, as query-string values.
pub async fn query_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/_queries/{name}");

    let Some(query) = state.ir.queries.iter().find(|q| q.name == name) else {
        return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
    };
    let Some(principal) = state.auth.authenticate(&headers) else {
        return problem_response(&Error::unauthenticated(), &instance, &req_id, vec![]);
    };
    let principal = Some(principal);
    let ctx = make_context(req_id.clone(), principal.clone());
    let scope = make_scope(principal.as_ref());

    let bad = |why: String| {
        problem_response(
            &Error::invalid_input("invalid_query_parameter", why),
            &instance,
            &req_id,
            vec![],
        )
    };
    if let Some(extra) = params
        .keys()
        .find(|k| !query.params.iter().any(|p| &p.name == *k))
    {
        return bad(format!("unknown parameter `{extra}`"));
    }
    let mut args: Vec<(String, Value)> = Vec::new();
    for p in &query.params {
        let Some(raw) = params.get(&p.name) else {
            return bad(format!("the parameter `{}` is required", p.name));
        };
        let value = match p.ty {
            falak_contracts::ir::FieldType::Text => {
                let normalised: String = raw.nfc().collect();
                let max = p.max_length.unwrap_or(1024) as usize;
                if normalised.chars().count() > max {
                    return bad(format!("`{}` is too long", p.name));
                }
                Value::Text(normalised)
            }
            falak_contracts::ir::FieldType::Int64
            | falak_contracts::ir::FieldType::DecimalMinor => match raw.parse::<i64>() {
                Ok(n) => Value::Int64(n),
                Err(_) => return bad(format!("`{}` must be a whole number", p.name)),
            },
            falak_contracts::ir::FieldType::Bool => match raw.as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => return bad(format!("`{}` must be true or false", p.name)),
            },
            falak_contracts::ir::FieldType::Uuid => match parse_uuid(raw) {
                Some(u) => Value::Uuid(u),
                None => return bad(format!("`{}` must be a uuid", p.name)),
            },
            _ => return bad(format!("`{}` has a type a query cannot take", p.name)),
        };
        args.push((p.name.clone(), value));
    }

    let mut accesses = Vec::new();
    for entity_name in &query.entities {
        let Some(entity) = find_entity(&state.ir, entity_name) else {
            return problem_response(
                &Error::internal("query names a missing entity"),
                &instance,
                &req_id,
                vec![],
            );
        };
        accesses.push((
            entity,
            authorize(entity, IrAction::Read, principal.as_ref()),
        ));
    }
    let statement = match sql::query(sql::QueryCall {
        ir: &state.ir,
        query,
        dialect: dialect_for_driver(&*state.driver),
        accesses: &accesses,
        scope: &scope,
        args: &args,
    }) {
        Ok(s) => s,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };
    let rows = match state.driver.query(&ctx, statement).await {
        Ok(r) => r,
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };
    let truncated = rows.rows.len() > sql::QUERY_MAX_ROWS as usize;
    let data: Vec<serde_json::Value> = rows
        .rows
        .iter()
        .take(sql::QUERY_MAX_ROWS as usize)
        .map(|r| row_to_json_object(None, &rows.columns, r))
        .collect();
    let body = serde_json::json!({ "data": data, "meta": { "truncated": truncated } });
    let mut res = (StatusCode::OK, body.to_string()).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&req_id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}
