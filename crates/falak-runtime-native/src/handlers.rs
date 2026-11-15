//! Request handlers for entity CRUD and commands.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

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
    ir::{IrAction, IrEntity},
};
use falak_core::{
    command::{self, Plan},
    policy::authorize,
    sql::{
        self, Condition, Dialect, Filter, ListQuery, Op, Request, Scope, SortKey, WriteContext,
        cursor_from_row,
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

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
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
            if let Some(field) = entity.field(fld) {
                let v_nfc: String = v.nfc().collect();
                if let Ok(val) = falak_core::values::coerce_text(field, &v_nfc) {
                    filters.push(Filter {
                        field: fld.to_string(),
                        condition: Condition::Compare(Op::Eq, val),
                    });
                }
            }
        }
    }

    let after = params.get("page[after]").and_then(|c| parse_cursor(c));

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
    let idempotency_scope = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| IdempotencyKeyScope {
            subject: scope.subject.clone().unwrap_or_default(),
            method: "POST".to_string(),
            path: instance.clone(),
            key: k.to_string(),
        });

    if let Some(ref iscope) = idempotency_scope {
        match state.idempotency.check_or_start(iscope, &payload_hash) {
            Ok(CheckResult::Proceed) => {}
            Ok(CheckResult::Replay(cached)) => {
                let json_val =
                    serde_json::from_slice(&cached.body).unwrap_or(serde_json::Value::Null);
                return build_response(cached.status, json_val, cached.etag, &req_id, true);
            }
            Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
        }
    }

    let json_body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
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
            state.idempotency.release(iscope);
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
                state.idempotency.release(iscope);
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
                    state.idempotency.release(iscope);
                }
                return problem_response(&e, &instance, &req_id, vec![]);
            }
        }
    }

    let access = authorize(entity, IrAction::Create, principal.as_ref());
    if access.is_denied() {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope);
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
                state.idempotency.release(iscope);
            }
            return problem_response(&Error::forbidden(), &instance, &req_id, vec![]);
        }
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let outcomes = match state.driver.batch(&ctx, vec![stmt]).await {
        Ok(o) => o,
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
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
        state.idempotency.complete(
            iscope,
            payload_hash,
            CachedResponse {
                status: StatusCode::CREATED,
                etag: Some("1".to_string()),
                body: response_json.to_string().into_bytes(),
            },
        );
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
    let idempotency_scope = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| IdempotencyKeyScope {
            subject: scope.subject.clone().unwrap_or_default(),
            method: "PATCH".to_string(),
            path: instance.clone(),
            key: k.to_string(),
        });

    if let Some(ref iscope) = idempotency_scope {
        match state.idempotency.check_or_start(iscope, &payload_hash) {
            Ok(CheckResult::Proceed) => {}
            Ok(CheckResult::Replay(cached)) => {
                let json_val =
                    serde_json::from_slice(&cached.body).unwrap_or(serde_json::Value::Null);
                return build_response(cached.status, json_val, cached.etag, &req_id, true);
            }
            Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
        }
    }

    let json_body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
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
            state.idempotency.release(iscope);
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
                state.idempotency.release(iscope);
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
                    state.idempotency.release(iscope);
                }
                return problem_response(&e, &instance, &req_id, vec![]);
            }
        }
    }

    let access = authorize(entity, IrAction::Update, principal.as_ref());
    if access.is_denied() {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope);
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
                state.idempotency.release(iscope);
            }
            return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
        }
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let outcomes = match state.driver.batch(&ctx, vec![stmt]).await {
        Ok(o) => o,
        Err(e) => {
            if let Some(ref iscope) = idempotency_scope {
                state.idempotency.release(iscope);
            }
            return problem_response(&e, &instance, &req_id, vec![]);
        }
    };

    let outcome = outcomes.into_iter().next().unwrap_or_default();
    if outcome.rows_affected == 0 {
        if let Some(ref iscope) = idempotency_scope {
            state.idempotency.release(iscope);
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
        state.idempotency.complete(
            iscope,
            payload_hash,
            CachedResponse {
                status: StatusCode::OK,
                etag: new_version,
                body: updated_json.to_string().into_bytes(),
            },
        );
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

    let outcomes = match state.driver.batch(&ctx, vec![stmt]).await {
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

    let Some(command) = state.ir.commands.iter().find(|c| c.name == cmd_name) else {
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

    let access = authorize(entity, IrAction::Update, principal.as_ref());
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
            return problem_response(&Error::not_found(), &instance, &req_id, vec![]);
        }
        Err(e) => return problem_response(&e, &instance, &req_id, vec![]),
    };

    let outcomes = match state.driver.batch(&ctx, vec![plan]).await {
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
