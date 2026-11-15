//! File uploads and downloads over HTTP (T3.11, ARCHITECTURE §4.7).
//!
//! * `POST /v1/_files` `{name, content_type, size}`: checks the type and size, records a
//!   pending file for the caller and returns a presigned upload URL into quarantine.
//! * `POST /v1/_files/{id}/complete`: checks what was uploaded against what was declared
//!   (size and magic bytes). A good file is published; a bad one is deleted.
//! * `GET /v1/_files/{id}`: a short-lived download URL, served as an attachment.
//!
//! A file belongs to the person who uploaded it and to their tenant. Another person, or
//! another tenant, gets `404` for every one of these, the same as for an id that does not
//! exist. Object keys are made here, under the tenant, and never taken from a request.
//! The table `_falak_files` is made by `falak migrate`.

use std::{future::Future, pin::Pin, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use falak_contracts::{
    Error, Result,
    driver::{Statement, Value},
    support::{Clock, IdGenerator},
};
use falak_core::{sql::Dialect, values::format_uuid, values::parse_uuid};
use serde_json::json;

use crate::{
    app::AppState,
    context::{extract_request_id, make_context},
    driver::NativeDriver,
    error::problem_response,
};

type Boxed<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What a client needs to upload.
#[derive(Debug, Clone)]
pub struct UploadTicket {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub expires_in_secs: u32,
}

/// The object store behind the file routes.
pub trait FileApi: Send + Sync + 'static {
    fn begin(
        &self,
        tenant: Option<&str>,
        id: &str,
        content_type: &str,
        size: u64,
    ) -> Result<UploadTicket>;

    fn finish<'a>(
        &'a self,
        tenant: Option<&'a str>,
        id: &'a str,
        content_type: &'a str,
        size: u64,
    ) -> Boxed<'a, ()>;

    fn download(&self, tenant: Option<&str>, id: &str, name: &str) -> Result<String>;
}

/// S3 and R2, from the environment: `FALAK_S3_ENDPOINT`, `FALAK_S3_BUCKET`,
/// `FALAK_S3_ACCESS_KEY`, `FALAK_S3_SECRET_KEY`, and optionally `FALAK_S3_REGION`
/// (default `auto`) and `FALAK_S3_PATH_STYLE` (default on).
#[cfg(feature = "files")]
pub struct S3Files {
    flow: Arc<falak_storage::FileFlow<falak_storage::s3::S3Backend>>,
}

#[cfg(feature = "files")]
impl S3Files {
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let config = falak_storage::S3Config {
            endpoint: get("FALAK_S3_ENDPOINT")?,
            bucket: get("FALAK_S3_BUCKET")?,
            region: get("FALAK_S3_REGION").unwrap_or_else(|| "auto".into()),
            access_key: get("FALAK_S3_ACCESS_KEY")?,
            secret_key: get("FALAK_S3_SECRET_KEY")?,
            path_style: get("FALAK_S3_PATH_STYLE").is_none_or(|v| v != "0"),
        };
        Some(Self {
            flow: Arc::new(falak_storage::FileFlow {
                backend: falak_storage::s3::S3Backend {
                    config: config.clone(),
                },
                config,
                limits: falak_storage::UploadLimits::default(),
            }),
        })
    }
}

#[cfg(feature = "files")]
fn now_secs() -> i64 {
    falak_contracts::support::wall_clock_micros() / 1_000_000
}

#[cfg(feature = "files")]
impl FileApi for S3Files {
    fn begin(
        &self,
        tenant: Option<&str>,
        id: &str,
        content_type: &str,
        size: u64,
    ) -> Result<UploadTicket> {
        let b = self
            .flow
            .begin_upload(tenant, id, content_type, size, now_secs())?;
        Ok(UploadTicket {
            url: b.url,
            headers: b.headers,
            expires_in_secs: b.expires_in_secs,
        })
    }

    fn finish<'a>(
        &'a self,
        tenant: Option<&'a str>,
        id: &'a str,
        content_type: &'a str,
        size: u64,
    ) -> Boxed<'a, ()> {
        let flow = self.flow.clone();
        let (tenant, id, content_type) = (
            tenant.map(str::to_owned),
            id.to_owned(),
            content_type.to_owned(),
        );
        Box::pin(async move {
            // The store is reached with blocking calls, so it runs off the async threads.
            tokio::task::spawn_blocking(move || {
                block_on(flow.finish_upload(tenant.as_deref(), &id, &content_type, size))
            })
            .await
            .map_err(|_| Error::internal("the file check did not finish"))?
            .map(|_| ())
        })
    }

    fn download(&self, tenant: Option<&str>, id: &str, name: &str) -> Result<String> {
        self.flow.download_url(tenant, id, name, now_secs())
    }
}

/// Run a future that never waits (the S3 backend's calls block instead).
#[cfg(feature = "files")]
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

// ------------------------------------------------------------------ the routes

fn dialect<D: NativeDriver>(d: &D) -> Dialect {
    match d.profile().name {
        "postgres" => Dialect::Postgres,
        "d1" => Dialect::D1,
        _ => Dialect::Sqlite,
    }
}

fn ph(d: Dialect, n: usize) -> String {
    if d == Dialect::Postgres {
        format!("${n}")
    } else {
        format!("?{n}")
    }
}

/// `tenant = ?n`, or `tenant IS NULL` when the app has none.
fn tenant_cond(d: Dialect, tenant: Option<&str>, n: usize, params: &mut Vec<Value>) -> String {
    match tenant {
        Some(t) => {
            params.push(Value::Text(t.to_owned()));
            format!("\"tenant\" = {}", ph(d, n))
        }
        None => "\"tenant\" IS NULL".to_owned(),
    }
}

struct Row {
    name: String,
    content_type: String,
    size: u64,
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::Text(s)) => s.clone(),
        _ => String::new(),
    }
}

/// The caller's own file in `state`, if there is one. Someone else's is the same as none.
async fn find<D: NativeDriver>(
    state: &AppState<D>,
    ctx: &falak_contracts::identity::RequestContext,
    id: &str,
    subject: &str,
    tenant: Option<&str>,
    wanted: &str,
) -> Result<Option<Row>> {
    let d = dialect(&*state.driver);
    let mut params = vec![
        Value::Text(id.to_owned()),
        Value::Text(subject.to_owned()),
        Value::Text(wanted.to_owned()),
    ];
    let tenant_sql = tenant_cond(d, tenant, 4, &mut params);
    let sql = format!(
        "SELECT \"name\", \"content_type\", \"size\" FROM \"_falak_files\" \
         WHERE \"id\" = {} AND \"owner\" = {} AND \"state\" = {} AND {tenant_sql}",
        ph(d, 1),
        ph(d, 2),
        ph(d, 3)
    );
    let rows = state.driver.query(ctx, Statement::new(sql, params)).await?;
    Ok(rows.rows.first().map(|r| Row {
        name: text(r.first()),
        content_type: text(r.get(1)),
        size: match r.get(2) {
            Some(Value::Int64(n)) => u64::try_from(*n).unwrap_or(0),
            _ => 0,
        },
    }))
}

async fn set_state<D: NativeDriver>(
    state: &AppState<D>,
    ctx: &falak_contracts::identity::RequestContext,
    id: &str,
    new_state: &str,
) -> Result<()> {
    let d = dialect(&*state.driver);
    let sql = format!(
        "UPDATE \"_falak_files\" SET \"state\" = {} WHERE \"id\" = {}",
        ph(d, 1),
        ph(d, 2)
    );
    state
        .driver
        .batch(
            ctx,
            vec![Statement::new(
                sql,
                vec![
                    Value::Text(new_state.to_owned()),
                    Value::Text(id.to_owned()),
                ],
            )],
        )
        .await
        .map(|_| ())
}

fn json_response(status: StatusCode, body: &serde_json::Value, request_id: &str) -> Response {
    let mut res = (status, body.to_string()).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(request_id) {
        h.insert("x-request-id", v);
    }
    res
}

fn unsupported() -> Error {
    Error::unsupported(
        "files_not_configured",
        "File storage is not set up for this app.",
    )
}

fn file_id(raw: &str) -> Option<String> {
    parse_uuid(raw).map(|u| format_uuid(&u))
}

pub async fn begin_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = "/v1/_files";
    let fail = |e: Error| problem_response(&e, instance, &req_id, vec![]);
    let Some(principal) = state.auth.authenticate(&headers) else {
        return fail(Error::unauthenticated());
    };
    let Some(files) = &state.files else {
        return fail(unsupported());
    };
    let Ok(input) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return fail(Error::invalid_input(
            "invalid_body",
            "The body must be JSON.",
        ));
    };
    let (Some(name), Some(content_type), Some(size)) = (
        input["name"].as_str(),
        input["content_type"].as_str(),
        input["size"].as_u64(),
    ) else {
        return fail(Error::invalid_input(
            "invalid_body",
            "`name`, `content_type` and `size` are required.",
        ));
    };
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return fail(Error::invalid_input(
            "invalid_name",
            "The file name is not valid.",
        ));
    }
    let id = format_uuid(&falak_auth::system::RandomIds.new_id());
    let ticket = match files.begin(principal.tenant.as_deref(), &id, content_type, size) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let ctx = make_context(req_id.clone(), Some(principal.clone()));
    let d = dialect(&*state.driver);
    let sql = format!(
        "INSERT INTO \"_falak_files\" (\"id\", \"tenant\", \"owner\", \"name\", \"content_type\", \"size\", \"state\", \"created_at\") \
         VALUES ({}, {}, {}, {}, {}, {}, 'pending', {})",
        ph(d, 1),
        ph(d, 2),
        ph(d, 3),
        ph(d, 4),
        ph(d, 5),
        ph(d, 6),
        ph(d, 7)
    );
    let params = vec![
        Value::Text(id.clone()),
        principal.tenant.clone().map_or(Value::Null, Value::Text),
        Value::Text(principal.subject.clone()),
        Value::Text(name.to_owned()),
        Value::Text(content_type.to_owned()),
        Value::Int64(i64::try_from(size).unwrap_or(i64::MAX)),
        Value::Int64(falak_auth::system::SystemClock.now_micros()),
    ];
    if let Err(e) = state
        .driver
        .batch(&ctx, vec![Statement::new(sql, params)])
        .await
    {
        return fail(e);
    }
    let headers_json: serde_json::Map<String, serde_json::Value> = ticket
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    json_response(
        StatusCode::CREATED,
        &json!({
            "id": id,
            "state": "pending",
            "upload": {
                "method": "PUT",
                "url": ticket.url,
                "headers": headers_json,
                "expires_in": ticket.expires_in_secs,
            }
        }),
        &req_id,
    )
}

pub async fn complete_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/_files/{id}/complete");
    let fail = |e: Error| problem_response(&e, &instance, &req_id, vec![]);
    let Some(principal) = state.auth.authenticate(&headers) else {
        return fail(Error::unauthenticated());
    };
    let Some(files) = &state.files else {
        return fail(unsupported());
    };
    let Some(id) = file_id(&id) else {
        return fail(Error::not_found());
    };
    let ctx = make_context(req_id.clone(), Some(principal.clone()));
    let tenant = principal.tenant.as_deref();
    let row = match find(&state, &ctx, &id, &principal.subject, tenant, "pending").await {
        Ok(Some(r)) => r,
        Ok(None) => return fail(Error::not_found()),
        Err(e) => return fail(e),
    };
    match files.finish(tenant, &id, &row.content_type, row.size).await {
        Ok(()) => {
            if let Err(e) = set_state(&state, &ctx, &id, "clean").await {
                return fail(e);
            }
            json_response(
                StatusCode::OK,
                &json!({"id": id, "state": "clean"}),
                &req_id,
            )
        }
        Err(e) => {
            // The file was refused and removed from quarantine. Keep the record's state
            // honest, so the same id cannot be completed again.
            let _ = set_state(&state, &ctx, &id, "rejected").await;
            fail(e)
        }
    }
}

pub async fn get_handler<D: NativeDriver>(
    State(state): State<Arc<AppState<D>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let req_id = extract_request_id(&headers);
    let instance = format!("/v1/_files/{id}");
    let fail = |e: Error| problem_response(&e, &instance, &req_id, vec![]);
    let Some(principal) = state.auth.authenticate(&headers) else {
        return fail(Error::unauthenticated());
    };
    let Some(files) = &state.files else {
        return fail(unsupported());
    };
    let Some(id) = file_id(&id) else {
        return fail(Error::not_found());
    };
    let ctx = make_context(req_id.clone(), Some(principal.clone()));
    let tenant = principal.tenant.as_deref();
    let row = match find(&state, &ctx, &id, &principal.subject, tenant, "clean").await {
        Ok(Some(r)) => r,
        Ok(None) => return fail(Error::not_found()),
        Err(e) => return fail(e),
    };
    let url = match files.download(tenant, &id, &row.name) {
        Ok(u) => u,
        Err(e) => return fail(e),
    };
    json_response(
        StatusCode::OK,
        &json!({
            "id": id,
            "name": row.name,
            "content_type": row.content_type,
            "size": row.size,
            "download": { "url": url },
        }),
        &req_id,
    )
}
