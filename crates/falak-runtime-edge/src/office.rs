//! Following Falak Office from a Worker (T4.6, FEDERATION specification).
//!
//! The Worker is enrolled like any app (`falak office enroll`, then `falak deploy`). It
//! gets its Office configuration in the variable `FALAK_OFFICE_CONFIG` and its own key in
//! the secret `FALAK_APP_KEY`. Isolates share no memory and have no timers, so the Worker
//! keeps up with Office on requests: at most once every [`SYNC_SECS`] per isolate it
//! fetches the revocation feed (a signed request), and it fetches the key set when it is
//! stale or when a token names a key it does not know.
//!
//! The decisions are the same as on the native runtime (`falak-federation`): tier 1 keeps
//! serving when Office is gone; tier 2 reads but pauses writes once the feed is older than
//! the staleness limit.

use std::sync::{Arc, Mutex};

use falak_contracts::{
    driver::{Statement, Value as Sql},
    identity::RequestContext,
};
use falak_federation::{AppKey, Federation, OfficeConfig, now, random_nonce, request_headers};
use falak_runtime_native::driver::NativeDriver;
use serde_json::Value;
use worker::{Fetch, Headers, Method, Request, RequestInit};

const SYNC_SECS: i64 = 20;
const RETRY_AFTER_FAILURE_SECS: i64 = 5;
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Save again at least this often while nothing changes, so a restored instance sees a
/// recent time for the last feed.
const SAVE_EVERY_SECS: i64 = 120;

pub struct OfficeLink {
    fed: Arc<Federation>,
    cfg: OfficeConfig,
    key: AppKey,
    /// Where the last good key set and feed are kept between isolates.
    store: Arc<dyn NativeDriver>,
    state: Mutex<Attempts>,
}

#[derive(Default)]
struct Attempts {
    last_sync: Option<i64>,
    last_attempt: Option<i64>,
    /// The saved state has been read (once per isolate).
    loaded: bool,
    /// What was last saved: the key set text, the feed version, and when.
    saved: Option<(String, i64, i64)>,
    jwks_text: String,
}

const CACHE_TABLE: &str = "falak_office_cache";

impl OfficeLink {
    pub fn new(
        config_json: &str,
        key_json: &str,
        max_staleness_secs: i64,
        store: Arc<dyn NativeDriver>,
    ) -> Result<Self, String> {
        let cfg = OfficeConfig::from_json(config_json)?;
        Ok(Self {
            fed: Arc::new(Federation::new(&cfg, max_staleness_secs)),
            key: AppKey::from_json(key_json)?,
            cfg,
            store,
            state: Mutex::new(Attempts::default()),
        })
    }

    pub fn federation(&self) -> Arc<Federation> {
        self.fed.clone()
    }

    pub fn config(&self) -> &OfficeConfig {
        &self.cfg
    }

    pub fn key(&self) -> &AppKey {
        &self.key
    }

    /// Fetch Office's key set now, for an event that names a key not seen before.
    pub async fn reload_keys(&self) {
        if let Err(why) = self.load_keys(now()).await {
            worker::console_error!("falak: Office: {why}");
        }
    }

    /// Keep up with Office. Call before routing; the authenticator cannot do I/O.
    pub async fn refresh_if_needed(&self, token: Option<&str>) {
        self.load_saved().await;
        let t = now();
        let want_keys =
            self.fed.wants_jwks(t) || token.is_some_and(|k| self.fed.wants_jwks_for(k, t));
        let want_feed = {
            let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            s.last_sync.is_none_or(|l| t - l >= SYNC_SECS)
        };
        if !want_keys && !want_feed {
            return;
        }
        {
            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if s.last_attempt
                .is_some_and(|a| t - a < RETRY_AFTER_FAILURE_SECS)
            {
                return;
            }
            s.last_attempt = Some(t);
        }
        let result = async {
            if want_keys {
                self.load_keys(t).await?;
            }
            if want_feed {
                let doc = self.signed_get(&self.fed.feed_path()).await?;
                if let Err(first) = self.fed.apply_document(&doc, now()) {
                    // Signed by a key we have not seen: one refetch of the key set.
                    self.load_keys(t).await?;
                    self.fed.apply_document(&doc, now()).map_err(|_| first)?;
                }
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .last_sync = Some(now());
            }
            Ok::<(), String>(())
        }
        .await;
        match result {
            Ok(()) => self.save().await,
            Err(why) => {
                worker::console_error!("falak: Office: {why}");
                self.fed.note_error(why);
            }
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            principal: None,
            request_id: "falak-office".into(),
        }
    }

    /// A new isolate starts from what the last one saved, so that it can check tokens and
    /// keep honoring revocations while Office cannot be reached.
    async fn load_saved(&self) {
        {
            let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if s.loaded {
                return;
            }
            s.loaded = true;
        }
        let read = |k: &'static str| {
            Statement::new(
                format!("SELECT v FROM {CACHE_TABLE} WHERE k = ?1"),
                vec![Sql::Text(k.to_owned())],
            )
        };
        let get = |rows: falak_contracts::driver::Rows| {
            rows.rows.first().and_then(|r| match r.first() {
                Some(Sql::Text(t)) => Some(t.clone()),
                _ => None,
            })
        };
        // The table may not exist yet: then there is nothing saved.
        let (Ok(jwks), Ok(feed)) = (
            self.store.query(&Self::ctx(), read("jwks")).await,
            self.store.query(&Self::ctx(), read("feed")).await,
        ) else {
            return;
        };
        if let Some(text) = get(jwks)
            && self.fed.load_jwks(&text, now()).is_ok()
        {
            // Loaded from a save: treat the key set as old, so it is refreshed at once.
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .jwks_text = text;
        }
        if let Some(v) = get(feed).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
            self.fed.restore(&v);
        }
    }

    /// Save what was just learned, when it changed or the last save is getting old.
    async fn save(&self) {
        let (jwks, snap) = {
            let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (s.jwks_text.clone(), self.fed.snapshot())
        };
        let version = snap["feed_version"].as_i64().unwrap_or(0);
        let t = now();
        {
            let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((j, v, at)) = &s.saved
                && *j == jwks
                && *v == version
                && t - *at < SAVE_EVERY_SECS
            {
                return;
            }
        }
        let put = |k: &'static str, v: String| {
            Statement::new(
                format!(
                    "INSERT INTO {CACHE_TABLE} (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v"
                ),
                vec![Sql::Text(k.to_owned()), Sql::Text(v)],
            )
        };
        let batch = vec![
            Statement::new(
                format!(
                    "CREATE TABLE IF NOT EXISTS {CACHE_TABLE} (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
                ),
                vec![],
            ),
            put("jwks", jwks.clone()),
            put("feed", snap.to_string()),
        ];
        match self.store.batch(&Self::ctx(), batch).await {
            Ok(_) => {
                self.state.lock().unwrap_or_else(|p| p.into_inner()).saved =
                    Some((jwks, version, t));
            }
            Err(e) => {
                worker::console_error!("falak: cannot save Office's state: {}", e.public_message())
            }
        }
    }

    async fn load_keys(&self, t: i64) -> Result<(), String> {
        let req = Request::new(&self.cfg.jwks_url, Method::Get).map_err(|e| e.to_string())?;
        let text = text_of(req).await?;
        self.fed.load_jwks(&text, t)?;
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .jwks_text = text;
        Ok(())
    }

    async fn signed_get(&self, path: &str) -> Result<Value, String> {
        let headers = Headers::new();
        for (k, v) in request_headers(
            &self.key,
            &self.cfg.app,
            "GET",
            path,
            b"",
            now(),
            &random_nonce(),
        ) {
            headers.set(&k, &v).map_err(|e| e.to_string())?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);
        let url = format!("{}{path}", self.cfg.office_url.trim_end_matches('/'));
        let req = Request::new_with_init(&url, &init).map_err(|e| e.to_string())?;
        serde_json::from_str(&text_of(req).await?)
            .map_err(|_| "Office sent something unreadable".to_owned())
    }
}

async fn text_of(req: Request) -> Result<String, String> {
    let mut res = Fetch::Request(req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status_code() != 200 {
        return Err(format!("Office answered {}", res.status_code()));
    }
    let text = res.text().await.map_err(|e| e.to_string())?;
    if text.len() > MAX_BODY_BYTES {
        return Err("Office's answer is too large".into());
    }
    Ok(text)
}
