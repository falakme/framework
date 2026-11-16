//! The Office Compute queue (T7.2) and its credentials (T7.4), over SQLite.

use std::sync::Arc;

use falak_contracts::jobs::{Job, JobDispatcher};
use falak_driver_sqlite::SqliteDriver;
use falak_office::{
    compute::{Queue, job_id_hex},
    db::Db,
};

const SEC: i64 = 1_000_000;

async fn db() -> Db {
    let db = Db::new(Arc::new(SqliteDriver::in_memory().await.unwrap()));
    db.migrate().await.unwrap();
    db
}

fn job(n: u8) -> Job {
    Job {
        id: [n; 16],
        kind: "scan".into(),
        payload: br#"{"document_id":"x"}"#.to_vec(),
        attempts: 0,
        run_at_micros: 0,
    }
}

fn kinds() -> Vec<String> {
    vec!["scan".into()]
}

#[tokio::test]
async fn a_lease_hides_the_job_until_it_lapses_and_a_heartbeat_extends_it() {
    let db = db().await;
    Queue::at(&db, 0).enqueue(job(1)).await.unwrap();
    // The same id twice queues one job.
    Queue::at(&db, 0).enqueue(job(1)).await.unwrap();

    let l = Queue::at(&db, SEC)
        .lease_for("w1", &kinds(), 5, 10_000)
        .await
        .unwrap();
    assert_eq!(l.len(), 1);
    let lease = &l[0].lease;
    assert_eq!(lease.job.attempts, 1);
    // Held: nobody else gets it.
    assert!(
        Queue::at(&db, 5 * SEC)
            .lease_for("w2", &kinds(), 5, 10_000)
            .await
            .unwrap()
            .is_empty()
    );
    // A heartbeat at 9s keeps it past the original 11s expiry.
    Queue::at(&db, 9 * SEC)
        .heartbeat(&lease.lease_id, 10_000)
        .await
        .unwrap();
    assert!(
        Queue::at(&db, 12 * SEC)
            .lease_for("w2", &kinds(), 5, 10_000)
            .await
            .unwrap()
            .is_empty()
    );
    // Past the extended expiry the job is due again.
    assert_eq!(
        Queue::at(&db, 30 * SEC)
            .lease_for("w2", &kinds(), 5, 10_000)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_lost_lease_cannot_complete_and_a_repeated_completion_is_harmless() {
    let db = db().await;
    Queue::at(&db, 0).enqueue(job(2)).await.unwrap();
    let first = Queue::at(&db, SEC)
        .lease_for("w1", &kinds(), 1, 5_000)
        .await
        .unwrap();
    // w1 dies. w2 takes the job after the lease lapses.
    let second = Queue::at(&db, 20 * SEC)
        .lease_for("w2", &kinds(), 1, 5_000)
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].lease.job.attempts, 2);
    // w1 comes back: its completion is refused, w2's is accepted.
    let q = Queue::at(&db, 21 * SEC);
    assert!(q.complete(&first[0].lease.lease_id).await.is_err());
    q.complete(&second[0].lease.lease_id).await.unwrap();
    // Completing again changes nothing and is not an error.
    q.complete(&second[0].lease.lease_id).await.unwrap();
    let s = q.status(&job_id_hex(&[2; 16])).await.unwrap().unwrap();
    assert_eq!((s.status.as_str(), s.attempts), ("done", 2));
    // Nothing is left to lease.
    assert!(
        Queue::at(&db, 99 * SEC)
            .lease_for("w3", &kinds(), 1, 5_000)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_failed_job_retries_and_then_dead_letters() {
    let db = db().await;
    let q = Queue::at(&db, 0);
    q.enqueue_with(&job(3), "{}", 2).await.unwrap();
    let a = Queue::at(&db, SEC)
        .lease_for("w", &kinds(), 1, 5_000)
        .await
        .unwrap();
    Queue::at(&db, SEC)
        .fail(&a[0].lease.lease_id, true, "boom")
        .await
        .unwrap();
    // Backed off, then due again.
    assert!(
        Queue::at(&db, SEC)
            .lease_for("w", &kinds(), 1, 5_000)
            .await
            .unwrap()
            .is_empty()
    );
    let b = Queue::at(&db, 60 * SEC)
        .lease_for("w", &kinds(), 1, 5_000)
        .await
        .unwrap();
    assert_eq!(b[0].lease.job.attempts, 2);
    // The last attempt may not retry.
    Queue::at(&db, 60 * SEC)
        .fail(&b[0].lease.lease_id, true, "boom again")
        .await
        .unwrap();
    let dead = q.dead_letters().await.unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].last_error.as_deref(), Some("boom again"));
    assert!(
        Queue::at(&db, 999 * SEC)
            .lease_for("w", &kinds(), 1, 5_000)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_job_that_keeps_losing_its_lease_is_dead_lettered() {
    let db = db().await;
    Queue::at(&db, 0)
        .enqueue_with(&job(4), "{}", 1)
        .await
        .unwrap();
    Queue::at(&db, SEC)
        .lease_for("w", &kinds(), 1, 1_000)
        .await
        .unwrap();
    // The only attempt lapsed with no result.
    let q = Queue::at(&db, 60 * SEC);
    assert!(
        q.lease_for("w", &kinds(), 1, 1_000)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(q.dead_letters().await.unwrap().len(), 1);
}

#[tokio::test]
async fn worker_credentials_are_revocable_and_job_credentials_are_scoped() {
    let db = db().await;
    let q = Queue::at(&db, 0);
    let (id, cred) = q.create_worker("box-1").await.unwrap();
    assert_eq!(q.verify_worker(&cred).await.unwrap(), Some(id.clone()));
    assert_eq!(
        q.verify_worker(&format!("{cred}x")).await.unwrap(),
        None,
        "a wrong secret is refused"
    );

    q.enqueue_with(&job(5), r#"{"egress":["api.example.com"]}"#, 3)
        .await
        .unwrap();
    let held = Queue::at(&db, SEC)
        .lease_for(&id, &kinds(), 1, 30_000)
        .await
        .unwrap();
    let token = held[0].credential.clone();
    let live = Queue::at(&db, 2 * SEC)
        .verify_job_token(&token)
        .await
        .unwrap();
    let (job_id, lease_id, egress) = live.unwrap();
    assert_eq!(job_id, job_id_hex(&[5; 16]));
    assert_eq!(lease_id, held[0].lease.lease_id);
    assert_eq!(egress, r#"["api.example.com"]"#);
    // Short-lived: dead once the lease would have lapsed.
    assert!(
        Queue::at(&db, 40 * SEC)
            .verify_job_token(&token)
            .await
            .unwrap()
            .is_none()
    );

    // Revoking the worker stops it now and frees its job.
    assert!(q.revoke_worker(&id).await.unwrap());
    assert_eq!(q.verify_worker(&cred).await.unwrap(), None);
    assert!(
        Queue::at(&db, 3 * SEC)
            .verify_job_token(&token)
            .await
            .unwrap()
            .is_none()
    );
    let again = Queue::at(&db, 3 * SEC)
        .lease_for("other", &kinds(), 1, 30_000)
        .await
        .unwrap();
    assert_eq!(again.len(), 1);
    // A job credential ends with its job.
    let t2 = again[0].credential.clone();
    Queue::at(&db, 4 * SEC)
        .complete(&again[0].lease.lease_id)
        .await
        .unwrap();
    assert!(
        Queue::at(&db, 4 * SEC)
            .verify_job_token(&t2)
            .await
            .unwrap()
            .is_none()
    );
}
