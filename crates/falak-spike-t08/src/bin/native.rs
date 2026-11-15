//! Native half of the T0.8 spike: the same request against SQLite. Prints the JSON body.

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    use falak_spike_t08::{Note, SCHEMA_SQL, SEED_SQL, SELECT_SQL, note_json, parse_path};
    use sqlx::{Connection, Row, SqliteConnection};

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/notes/1".to_string());
    let Some(id) = parse_path(&path) else {
        eprintln!("not found");
        std::process::exit(1);
    };
    let mut conn = SqliteConnection::connect("sqlite::memory:")
        .await
        .expect("open");
    sqlx::query(SCHEMA_SQL)
        .execute(&mut conn)
        .await
        .expect("schema");
    sqlx::query(SEED_SQL)
        .execute(&mut conn)
        .await
        .expect("seed");
    let row = sqlx::query(SELECT_SQL)
        .bind(id)
        .fetch_optional(&mut conn)
        .await
        .expect("query");
    let Some(row) = row else {
        eprintln!("not found");
        std::process::exit(1);
    };
    let note = Note {
        id: row.get("id"),
        title: row.get("title"),
        body: row.get("body"),
    };
    println!("{}", note_json(&note));
}

#[cfg(target_arch = "wasm32")]
fn main() {}
