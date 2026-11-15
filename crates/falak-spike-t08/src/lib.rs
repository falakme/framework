//! T0.8 spike. The portable part is `note_json` and the SQL below. It compiles for
//! `wasm32` (Workers, reading D1) and natively (reading SQLite) and must give the
//! same JSON for the same request.

use serde::Serialize;

/// The one hard-coded entity.
pub const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS notes (\
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL)";
pub const SEED_SQL: &str =
    "INSERT OR REPLACE INTO notes (id, title, body) VALUES (1, 'hello', 'same row on D1 and SQLite')";
pub const SELECT_SQL: &str = "SELECT id, title, body FROM notes WHERE id = ?1";

#[derive(Debug, Serialize)]
pub struct Note {
    pub id: i64,
    pub title: String,
    pub body: String,
}

/// The response body for `GET /notes/{id}`.
pub fn note_json(note: &Note) -> String {
    serde_json::to_string(note).unwrap_or_else(|_| "{}".to_string())
}

/// Pulls the id out of `/notes/{id}`.
pub fn parse_path(path: &str) -> Option<i64> {
    path.strip_prefix("/notes/")?.parse().ok()
}

#[cfg(target_arch = "wasm32")]
mod edge {
    use super::{Note, SELECT_SQL, note_json, parse_path};
    use worker::{Context, Env, Request, Response, Result, event};

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let path = req.path();
        let Some(id) = parse_path(&path) else {
            return Response::error("not found", 404);
        };
        let db = env.d1("DB")?;
        let row = db
            .prepare(SELECT_SQL)
            .bind(&[(id as f64).into()])?
            .first::<serde_json::Value>(None)
            .await?;
        let Some(row) = row else {
            return Response::error("not found", 404);
        };
        let note = Note {
            id: row["id"].as_i64().unwrap_or_default(),
            title: row["title"].as_str().unwrap_or_default().to_string(),
            body: row["body"].as_str().unwrap_or_default().to_string(),
        };
        let mut resp = Response::ok(note_json(&note))?;
        resp.headers_mut().set("content-type", "application/json")?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_is_stable() {
        let n = Note { id: 1, title: "hello".into(), body: "b".into() };
        assert_eq!(note_json(&n), r#"{"id":1,"title":"hello","body":"b"}"#);
    }

    #[test]
    fn path_parsing() {
        assert_eq!(parse_path("/notes/1"), Some(1));
        assert_eq!(parse_path("/notes/x"), None);
        assert_eq!(parse_path("/other"), None);
    }
}
