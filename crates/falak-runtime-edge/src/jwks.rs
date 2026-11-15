//! Token verification against another service's key set (T2.9).
//!
//! Used when the Worker is configured with `FALAK_JWKS_URL`: the issuer (for example
//! Office, or another Falak app) publishes its public keys, and this Worker checks
//! tokens against them without holding any signing key.
//!
//! The cache decides when to fetch ([`JwksCache`]). This module does the fetching, once
//! per isolate per ten minutes, plus once when a token names a key we do not know yet
//! (a rotation), never more often than every 30 seconds. A failed fetch keeps the old
//! keys, and is not retried for 5 seconds, so a dead issuer does not turn every request
//! into a fetch.

use std::sync::Mutex;

use axum::http::HeaderMap;
use falak_auth::{
    jwks::{CachePolicy, JwksCache},
    token::TokenConfig,
};
use falak_contracts::{identity::Principal, support::wall_clock_micros};
use falak_runtime_native::context::{Authenticator, bearer_token};
use worker::{Fetch, Url};

/// Largest key set accepted. A real one is a few hundred bytes.
const MAX_JWKS_BYTES: usize = 64 * 1024;
const RETRY_AFTER_FAILURE_SECS: i64 = 5;

pub struct JwksAuth {
    cache: Mutex<JwksCache>,
    url: Url,
    last_attempt: Mutex<Option<i64>>,
}

fn now_secs() -> i64 {
    wall_clock_micros() / 1_000_000
}

impl JwksAuth {
    /// `url` must be `https`. It comes from the Worker's own configuration, not from a
    /// request.
    pub fn new(url: &str, config: TokenConfig) -> Result<Self, String> {
        let url = Url::parse(url).map_err(|e| format!("FALAK_JWKS_URL is not a URL: {e}"))?;
        if url.scheme() != "https" {
            return Err("FALAK_JWKS_URL must be https".into());
        }
        Ok(Self {
            cache: Mutex::new(JwksCache::new(config, CachePolicy::default())),
            url,
            last_attempt: Mutex::new(None),
        })
    }

    /// Fetch the key set if it is stale, or if `token` names a key we do not know.
    /// Call before routing; [`Authenticator::authenticate`] cannot do I/O.
    pub async fn refresh_if_needed(&self, token: Option<&str>) {
        let now = now_secs();
        let needed = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.is_stale(now)
                || token
                    .and_then(JwksCache::kid_of)
                    .is_some_and(|kid| cache.should_refresh_for(&kid, now))
        };
        if !needed {
            return;
        }
        {
            let mut last = self.last_attempt.lock().unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|t| now - t < RETRY_AFTER_FAILURE_SECS) {
                return;
            }
            *last = Some(now);
        }
        match self.fetch().await {
            Ok(text) => {
                let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
                if let Err(e) = cache.load(&text, now) {
                    worker::console_error!("falak: the key set is not usable: {e}");
                }
            }
            Err(why) => worker::console_error!("falak: cannot fetch the key set: {why}"),
        }
    }

    async fn fetch(&self) -> Result<String, String> {
        let mut res = Fetch::Url(self.url.clone())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if res.status_code() != 200 {
            return Err(format!("the issuer answered {}", res.status_code()));
        }
        let text = res.text().await.map_err(|e| e.to_string())?;
        if text.len() > MAX_JWKS_BYTES {
            return Err("the key set is too large".into());
        }
        Ok(text)
    }
}

impl Authenticator for JwksAuth {
    fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .verify(token, now_secs())
            .ok()
    }
}
