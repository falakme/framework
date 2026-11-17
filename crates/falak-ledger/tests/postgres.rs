//! Runs against a real PostgreSQL. Set `FALAK_TEST_PG_URL` (a scratch database). Without
//! it the tests print a notice and pass, as the other database tests in this repository do.

use falak_ledger::{Command, Currency, Ledger, reconcile::Line};
use uuid::Uuid;

const SCOPE: &str = "test-tenant";

static SCHEMA: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn usd() -> Currency {
    Currency::new("USD").unwrap()
}

async fn ledger() -> Option<Ledger> {
    let Ok(url) = std::env::var("FALAK_TEST_PG_URL") else {
        eprintln!("FALAK_TEST_PG_URL is not set; skipping");
        return None;
    };
    let l = Ledger::connect(&url, 30).await.unwrap();
    // Installing replaces triggers, which takes locks; do it once, before any test posts.
    SCHEMA
        .get_or_init(|| async { l.install_schema(None).await.unwrap() })
        .await;
    Some(l)
}

fn id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

fn transfer(from: &str, to: &str, amount: i64) -> Command {
    Command::Transfer {
        from: from.into(),
        to: to.into(),
        amount,
        currency: usd(),
    }
}

async fn funded(l: &Ledger, amount: i64) -> (String, String) {
    let bank = id("bank");
    let acct = id("acct");
    l.create_account(&bank, usd(), true).await.unwrap();
    l.create_account(&acct, usd(), false).await.unwrap();
    l.execute(SCOPE, &id("fund"), &transfer(&bank, &acct, amount))
        .await
        .unwrap();
    (bank, acct)
}

#[tokio::test]
async fn concurrent_transfers_never_overdraw() {
    let Some(l) = ledger().await else { return };
    let (_bank, from) = funded(&l, 1_000).await;
    let to = id("dest");
    l.create_account(&to, usd(), false).await.unwrap();

    // 40 transfers of 100 from an account that holds 1000: exactly 10 may succeed.
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let (l, from, to) = (l.clone(), from.clone(), to.clone());
        tasks.push(tokio::spawn(async move {
            l.execute(SCOPE, &id("t"), &transfer(&from, &to, 100)).await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert!(
                matches!(e.code(), "ledger_insufficient_funds" | "ledger_busy"),
                "unexpected error {e}"
            ),
        }
    }
    assert!(ok <= 10, "{ok} transfers succeeded from a balance of 10");
    assert_eq!(l.balance(&from).await.unwrap(), 1_000 - 100 * ok);
    assert_eq!(l.balance(&to).await.unwrap(), 100 * ok);
    assert!(l.invariants().await.unwrap().holds());
}

#[tokio::test]
async fn idempotency_replays_and_refuses_a_changed_request() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 500).await;
    let b = id("b");
    l.create_account(&b, usd(), false).await.unwrap();
    let key = id("k");
    let first = l
        .execute(SCOPE, &key, &transfer(&a, &b, 200))
        .await
        .unwrap();
    let again = l
        .execute(SCOPE, &key, &transfer(&a, &b, 200))
        .await
        .unwrap();
    assert!(!first.replayed && again.replayed);
    assert_eq!(first.tx_id, again.tx_id);
    assert_eq!(l.balance(&b).await.unwrap(), 200);
    let other = l
        .execute(SCOPE, &key, &transfer(&a, &b, 201))
        .await
        .unwrap_err();
    assert_eq!(other.code(), "ledger_key_reused");

    // The same key used at once, many times, posts once.
    let key = id("race");
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (l, a, b, key) = (l.clone(), a.clone(), b.clone(), key.clone());
        tasks.push(tokio::spawn(async move {
            l.execute(SCOPE, &key, &transfer(&a, &b, 10)).await
        }));
    }
    let mut ids = std::collections::HashSet::new();
    for t in tasks {
        ids.insert(t.await.unwrap().unwrap().tx_id);
    }
    assert_eq!(ids.len(), 1);
    assert_eq!(l.balance(&b).await.unwrap(), 210);
}

#[tokio::test]
async fn the_same_key_in_two_scopes_does_not_collide() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 500).await;
    let b = id("b");
    l.create_account(&b, usd(), false).await.unwrap();
    let key = id("shared");
    let one = l
        .execute("tenant-one", &key, &transfer(&a, &b, 100))
        .await
        .unwrap();
    // Another caller with the same key and a different request posts its own transfer
    // instead of replaying, or being refused by, the first caller's.
    let two = l
        .execute("tenant-two", &key, &transfer(&a, &b, 50))
        .await
        .unwrap();
    assert!(!one.replayed && !two.replayed);
    assert_ne!(one.tx_id, two.tx_id);
    assert_eq!(l.balance(&b).await.unwrap(), 150);
    // Each scope still replays its own key.
    let again = l
        .execute("tenant-one", &key, &transfer(&a, &b, 100))
        .await
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.tx_id, one.tx_id);
}

#[tokio::test]
async fn reserve_capture_release_and_reverse() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 1_000).await;
    let shop = id("shop");
    l.create_account(&shop, usd(), false).await.unwrap();
    let hold = id("hold");
    l.execute(
        SCOPE,
        &id("r"),
        &Command::Reserve {
            hold: hold.clone(),
            account: a.clone(),
            amount: 600,
            currency: usd(),
        },
    )
    .await
    .unwrap();
    assert_eq!(l.balance(&a).await.unwrap(), 400);
    assert_eq!(l.balance(&hold).await.unwrap(), 600);
    // Spending more than the unreserved 400 fails.
    let e = l
        .execute(SCOPE, &id("t"), &transfer(&a, &shop, 401))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "ledger_insufficient_funds");
    // Capture part, release the rest.
    l.execute(
        SCOPE,
        &id("c"),
        &Command::Capture {
            hold: hold.clone(),
            to: shop.clone(),
            amount: 250,
        },
    )
    .await
    .unwrap();
    l.execute(SCOPE, &id("rel"), &Command::Release { hold: hold.clone() })
        .await
        .unwrap();
    assert_eq!(l.balance(&shop).await.unwrap(), 250);
    assert_eq!(l.balance(&a).await.unwrap(), 750);
    assert_eq!(l.balance(&hold).await.unwrap(), 0);
    // Reverse the first transfer into the shop: only once.
    let paid = l
        .execute(SCOPE, &id("t2"), &transfer(&a, &shop, 100))
        .await
        .unwrap();
    let rev = Command::Reverse { tx: paid.tx_id };
    l.execute(SCOPE, &id("rv1"), &rev).await.unwrap();
    assert_eq!(l.balance(&shop).await.unwrap(), 250);
    let twice = l.execute(SCOPE, &id("rv2"), &rev).await.unwrap_err();
    assert_eq!(twice.code(), "ledger_already_reversed");
    assert!(l.invariants().await.unwrap().holds());
}

#[tokio::test]
async fn currency_mismatch_is_refused() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 10).await;
    let e = id("eur");
    l.create_account(&e, Currency::new("EUR").unwrap(), false)
        .await
        .unwrap();
    let err = l
        .execute(SCOPE, &id("x"), &transfer(&a, &e, 1))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "ledger_currency_mismatch");
}

#[tokio::test]
async fn posted_rows_cannot_be_changed_or_unbalanced() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 10).await;
    let pool = l.pool();
    for sql in [
        "UPDATE ledger_entries SET amount = amount + 1",
        "DELETE FROM ledger_entries",
        "TRUNCATE ledger_entries",
        "UPDATE ledger_transactions SET kind = 'x'",
        "DELETE FROM ledger_idempotency",
    ] {
        let err = sqlx::query(sql).execute(pool).await.unwrap_err();
        assert!(
            err.to_string().contains("ledger_immutable"),
            "{sql} was not refused: {err}"
        );
    }
    // A hand-written unbalanced transaction cannot commit, even for the table owner.
    let tx_id = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO ledger_transactions (id, kind, currency) VALUES ($1, 'x', 'USD')")
        .bind(tx_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ledger_entries (tx_id, account_id, currency, amount) VALUES ($1, $2, 'USD', 5)",
    )
    .bind(tx_id)
    .bind(&a)
    .execute(&mut *tx)
    .await
    .unwrap();
    let err = tx.commit().await.unwrap_err();
    assert!(err.to_string().contains("ledger_unbalanced"), "{err}");
    // A hand-written overdraft cannot commit either.
    let tx_id = Uuid::new_v4();
    let b = id("b");
    l.create_account(&b, usd(), false).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO ledger_transactions (id, kind, currency) VALUES ($1, 'x', 'USD')")
        .bind(tx_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    for (acct, amount) in [(&b, -5i64), (&a, 5)] {
        sqlx::query(
            "INSERT INTO ledger_entries (tx_id, account_id, currency, amount) VALUES ($1, $2, 'USD', $3)",
        )
        .bind(tx_id)
        .bind(acct)
        .bind(amount)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    let err = tx.commit().await.unwrap_err();
    assert!(
        err.to_string().contains("ledger_insufficient_funds"),
        "{err}"
    );
}

#[tokio::test]
async fn settle_and_reconcile() {
    let Some(l) = ledger().await else { return };
    let (_bank, a) = funded(&l, 1_000).await;
    let rail = id("rail");
    l.create_account(&rail, usd(), true).await.unwrap();
    let r1 = id("W");
    let r2 = id("W");
    for (r, amt) in [(&r1, 100), (&r2, 250)] {
        l.execute(
            SCOPE,
            &id("s"),
            &Command::Settle {
                from: a.clone(),
                settlement: rail.clone(),
                amount: amt,
                currency: usd(),
                external_ref: r.clone(),
            },
        )
        .await
        .unwrap();
    }
    let line = |r: &str, amount| Line {
        external_ref: r.into(),
        currency: usd(),
        amount,
    };
    // The bank's statement, from the rail's side.
    l.import_statement(&id("st"), &rail, &[]).await.unwrap();
    let good = id("st");
    l.import_statement(&good, &rail, &[line(&r1, 100), line(&r2, 250)])
        .await
        .unwrap();
    assert!(l.reconcile(&good).await.unwrap().is_clean());
    let bad = id("st");
    l.import_statement(
        &bad,
        &rail,
        &[line(&r1, 100), line(&r2, 251), line("ghost", 5)],
    )
    .await
    .unwrap();
    let report = l.reconcile(&bad).await.unwrap();
    assert_eq!(report.mismatched.len(), 1);
    assert_eq!(report.missing_in_ledger.len(), 1);
    // The same settlement reference cannot be posted twice under two keys.
    let dup = l
        .execute(
            SCOPE,
            &id("s"),
            &Command::Settle {
                from: a.clone(),
                settlement: rail.clone(),
                amount: 1,
                currency: usd(),
                external_ref: r1.clone(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(dup.code(), "ledger_duplicate_reference");
}

struct Storefront {
    fail: bool,
}

impl falak_ledger::saga::Participant for Storefront {
    async fn call(
        &self,
        _app: &str,
        command: &str,
        _key: &str,
        _args: &serde_json::Value,
    ) -> Result<serde_json::Value, falak_contracts::Error> {
        if self.fail && command == "item.create" {
            return Err(falak_contracts::Error::new(
                falak_contracts::ErrorKind::Unavailable,
                "down",
                "down",
            ));
        }
        Ok(serde_json::Value::Null)
    }
}

#[tokio::test]
async fn checkout_saga_moves_money_or_gives_it_back() {
    use falak_ledger::saga::{HorizonParticipant, Outcome, Router, checkout, run};
    let Some(l) = ledger().await else { return };
    let (_bank, buyer) = funded(&l, 1_000).await;
    let school = id("school");
    l.create_account(&school, usd(), false).await.unwrap();
    let router = |fail| Router {
        horizon: HorizonParticipant {
            ledger: l.clone(),
            scope: "saga-tenant".into(),
        },
        storefront: Storefront { fail },
    };

    let failed = checkout(
        "shop",
        "item.create",
        serde_json::json!({ "id": "e" }),
        "item.delete",
        serde_json::json!({ "id": "e" }),
        &id("hold"),
        &buyer,
        &school,
        400,
        usd(),
    );
    let out = run(&id("saga"), &failed, &router(true), 3).await;
    assert!(matches!(out, Outcome::Compensated { failed_step: 1, .. }));
    assert_eq!(l.balance(&buyer).await.unwrap(), 1_000);
    assert_eq!(l.balance(&school).await.unwrap(), 0);

    let good = checkout(
        "shop",
        "item.create",
        serde_json::json!({ "id": "e" }),
        "item.delete",
        serde_json::json!({ "id": "e" }),
        &id("hold"),
        &buyer,
        &school,
        400,
        usd(),
    );
    let saga_id = id("saga");
    assert!(matches!(
        run(&saga_id, &good, &router(false), 3).await,
        Outcome::Completed
    ));
    // Running the same saga again changes nothing: every call is idempotent.
    assert!(matches!(
        run(&saga_id, &good, &router(false), 3).await,
        Outcome::Completed
    ));
    assert_eq!(l.balance(&buyer).await.unwrap(), 600);
    assert_eq!(l.balance(&school).await.unwrap(), 400);
    assert!(l.invariants().await.unwrap().holds());
}

#[tokio::test]
async fn an_account_whose_sum_leaves_the_i64_range_still_works() {
    let Some(l) = ledger().await else { return };
    // A bank may go negative and only collects debits: two huge transfers take it past
    // i64::MIN. Reading its balance used to fail, and with it every command that touched
    // it and the ledger-wide invariants check.
    let bank = id("bank");
    l.create_account(&bank, usd(), true).await.unwrap();
    for _ in 0..2 {
        let to = id("acct");
        l.create_account(&to, usd(), false).await.unwrap();
        l.execute(
            SCOPE,
            &id("big"),
            &transfer(&bank, &to, 9_000_000_000_000_000_000),
        )
        .await
        .unwrap();
    }
    assert_eq!(l.balance(&bank).await.unwrap(), i64::MIN);
    let to = id("acct");
    l.create_account(&to, usd(), false).await.unwrap();
    l.execute(SCOPE, &id("more"), &transfer(&bank, &to, 1))
        .await
        .unwrap();
    assert!(l.invariants().await.unwrap().holds());
}
