//! RFC 7807 problem details error mapping for Axum.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use falak_contracts::{Error, ErrorKind};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct InvalidParam {
    pub name: String,
    pub reason: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub instance: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invalid_params: Vec<InvalidParam>,
}

pub fn problem_response(
    error: &Error,
    instance: &str,
    request_id: &str,
    invalid_params: Vec<InvalidParam>,
) -> Response {
    let status_code = error.kind().http_status();
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let title = match error.kind() {
        ErrorKind::InvalidInput => "Bad Request",
        ErrorKind::Unauthenticated => "Unauthorized",
        ErrorKind::Forbidden => "Forbidden",
        ErrorKind::NotFound => "Not Found",
        ErrorKind::Conflict => "Conflict",
        ErrorKind::PreconditionFailed => "Precondition Failed",
        ErrorKind::Unprocessable => "Unprocessable Entity",
        ErrorKind::PayloadTooLarge => "Payload Too Large",
        ErrorKind::RateLimited => "Too Many Requests",
        ErrorKind::Unsupported => "Not Implemented",
        ErrorKind::Unavailable => "Service Unavailable",
        ErrorKind::Timeout => "Gateway Timeout",
        ErrorKind::Internal => "Internal Server Error",
    };

    let slug = match error.kind() {
        ErrorKind::InvalidInput => "invalid-input",
        ErrorKind::Unauthenticated => "unauthenticated",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::NotFound => "not-found",
        ErrorKind::Conflict => "conflict",
        ErrorKind::PreconditionFailed => "precondition-failed",
        ErrorKind::Unprocessable => "unprocessable",
        ErrorKind::PayloadTooLarge => "payload-too-large",
        ErrorKind::RateLimited => "rate-limited",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Unavailable => "unavailable",
        ErrorKind::Timeout => "timeout",
        ErrorKind::Internal => "internal-error",
    };

    let problem = ProblemDetails {
        problem_type: format!("https://falak.me/errors/{slug}"),
        title: title.to_string(),
        status: status_code,
        detail: error.public_message().to_string(),
        code: error.code().to_string(),
        instance: instance.to_string(),
        request_id: request_id.to_string(),
        invalid_params,
    };

    let json = serde_json::to_string(&problem).unwrap_or_else(|_| "{}".to_string());

    let mut res = (status, json).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json; charset=utf-8"),
    );
    if let Ok(val) = HeaderValue::from_str(request_id) {
        res.headers_mut().insert("x-request-id", val);
    }
    res
}
