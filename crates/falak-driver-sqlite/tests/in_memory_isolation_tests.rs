//! An "in-memory" driver must start empty even if a file from an earlier process with the
//! same process id was left in the temp dir, and must not leave its own file behind.
//!
//! This file holds a single test on purpose: it plants files at the paths the driver will
//! pick next, which would clobber databases of other tests running in the same process.

use falak_contracts::{
    driver::{Statement, StorageDriver},
    identity::RequestContext,
};
use falak_driver_sqlite::SqliteDriver;
use sqlx::{Connection, SqliteConnection};

#[tokio::test]
async fn in_memory_ignores_stale_files_and_cleans_up() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let stale = |id: u32| dir.join(format!("falak_mem_{pid}_{id}.db"));

    // A leftover from an older build at the path the first driver of this process will
    // use: a history table without the checksum column.
    for id in 1..=1 {
        let _ = std::fs::remove_file(stale(id));
        let url = format!("sqlite://{}?mode=rwc", stale(id).display());
        let mut c = SqliteConnection::connect(&url).await.unwrap();
        sqlx::query("CREATE TABLE _falak_migrations (version INTEGER, content_hash TEXT)")
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
    }

    let driver = SqliteDriver::in_memory().await.unwrap();
    let ctx = RequestContext {
        principal: None,
        request_id: "t".into(),
    };
    let rows = driver
        .query(
            &ctx,
            Statement::new(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = '_falak_migrations'",
                vec![],
            ),
        )
        .await
        .unwrap();
    assert_eq!(format!("{:?}", rows.rows[0][0]), "Int64(0)");

    drop(driver);
    for id in 1..=1 {
        assert!(!stale(id).exists(), "file {id} was not cleaned up");
    }
}
