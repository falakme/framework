//! Request context and principal extraction.

use axum::http::HeaderMap;
use falak_contracts::identity::{Principal, RequestContext};
use falak_core::sql::Scope;

/// Extract or generate a request ID from headers.
pub fn extract_request_id(headers: &HeaderMap) -> String {
    if let Some(val) = headers.get("x-request-id")
        && let Ok(s) = val.to_str()
        && !s.trim().is_empty()
    {
        s.trim().to_string()
    } else {
        format!(
            "req_{}",
            &falak_core::values::format_uuid(&generate_uuid())[..12]
        )
    }
}

/// Extract caller principal from headers or request extensions.
pub fn extract_principal(headers: &HeaderMap) -> Option<Principal> {
    if let Some(auth_val) = headers.get("authorization")
        && let Ok(auth_str) = auth_val.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let token = token.trim();
        // Support dev token format: "sub:<subject>" or "sub:<subject>,role:<role>" or raw subject
        if let Some(sub) = token.strip_prefix("sub:") {
            let mut parts = sub.split(',');
            let subject = parts.next().unwrap_or(token).to_string();
            let mut roles = Vec::new();
            for part in parts {
                if let Some(role) = part.strip_prefix("role:") {
                    roles.push(role.to_string());
                }
            }
            return Some(Principal {
                subject,
                tenant: None,
                roles,
            });
        }
        return Some(Principal {
            subject: token.to_string(),
            tenant: None,
            roles: vec![],
        });
    }
    None
}

pub fn make_context(request_id: String, principal: Option<Principal>) -> RequestContext {
    RequestContext {
        principal,
        request_id,
    }
}

pub fn make_scope(principal: Option<&Principal>) -> Scope {
    Scope {
        tenant: principal.and_then(|p| p.tenant.clone()),
        subject: principal.map(|p| p.subject.clone()),
    }
}

fn generate_uuid() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(now as u64).to_be_bytes());
    b[8..].copy_from_slice(&((now >> 64) as u64 ^ 0x0123_4567_89ab_cdef).to_be_bytes());
    b
}
