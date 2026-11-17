//! Load generator for `scripts/smoke/ledger.sh` (T8.6).
//!
//! Usage: `ledger_load <database-url> <run-id> <statement.csv>`
//!
//! 1. Funds 5 source accounts with 1000 each, then fires 40 concurrent transfers of 100
//!    from every one of them (4000 against a balance of 1000), in pairs sharing an
//!    idempotency key.
//! 2. Settles part of what arrived to an external rail, concurrently, and writes the
//!    external "bank statement" (CSV) from only the settlements the ledger acknowledged.
//!    The statement is built from this program's own records, not from the database, so
//!    reconciling it is a real cross-check.
//!
//! Prints one JSON line. Exits 1 if an account ended negative or money was created.

use std::{fmt::Write as _, sync::Arc};

use falak_ledger::{Command, Currency, Ledger};

const SOURCES: usize = 5;
const FUNDING: i64 = 1_000;
const TRANSFERS_PER_SOURCE: usize = 40;
const AMOUNT: i64 = 100;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, url, run, statement_path] = &args[..] else {
        eprintln!("usage: ledger_load <database-url> <run-id> <statement.csv>");
        std::process::exit(2);
    };
    let ledger = Ledger::connect(url, 40).await.expect("connect");
    ledger.install_schema(None).await.expect("schema");
    let usd = Currency::new("USD").unwrap();
    let transfer = |from: &str, to: &str, amount| Command::Transfer {
        from: from.into(),
        to: to.into(),
        amount,
        currency: usd,
    };

    let bank = format!("bank-{run}");
    let rail = format!("rail-{run}");
    ledger.create_account(&bank, usd, true).await.unwrap();
    ledger.create_account(&rail, usd, true).await.unwrap();
    let sources: Vec<String> = (0..SOURCES).map(|i| format!("src-{run}-{i}")).collect();
    let dests: Vec<String> = (0..SOURCES).map(|i| format!("dst-{run}-{i}")).collect();
    for (s, d) in sources.iter().zip(&dests) {
        ledger.create_account(s, usd, false).await.unwrap();
        ledger.create_account(d, usd, false).await.unwrap();
        ledger
            .execute(
                "load",
                &format!("fund-{run}-{s}"),
                &transfer(&bank, s, FUNDING),
            )
            .await
            .unwrap();
    }

    // 1. Concurrent transfers that together exceed every balance.
    let mut tasks = Vec::new();
    for (s, d) in sources.iter().zip(&dests) {
        for n in 0..TRANSFERS_PER_SOURCE {
            let (ledger, s, d) = (ledger.clone(), s.clone(), d.clone());
            let cmd = transfer(&s, &d, AMOUNT);
            // Requests come in pairs with one key: the second must replay, not post.
            let key = format!("xfer-{run}-{s}-{}", n / 2);
            tasks.push(tokio::spawn(async move {
                ledger.execute("load", &key, &cmd).await
            }));
        }
    }
    let (mut posted, mut refused, mut busy) = (0u32, 0u32, 0u32);
    for t in tasks {
        match t.await.unwrap() {
            Ok(p) if !p.replayed => posted += 1,
            Ok(_) => {}
            Err(e) if e.code() == "ledger_insufficient_funds" => refused += 1,
            Err(e) if e.code() == "ledger_busy" => busy += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // 2. Settle to the rail, concurrently; keep our own record of what was acknowledged.
    let acked = Arc::new(std::sync::Mutex::new(Vec::<(String, i64)>::new()));
    let mut tasks = Vec::new();
    for (i, d) in dests.iter().enumerate() {
        for n in 0..10 {
            let (ledger, d, acked) = (ledger.clone(), d.clone(), acked.clone());
            let reference = format!("WIRE-{run}-{i}-{n}");
            let cmd = Command::Settle {
                from: d,
                settlement: rail.clone(),
                amount: 50,
                currency: usd,
                external_ref: reference.clone(),
            };
            tasks.push(tokio::spawn(async move {
                if ledger
                    .execute("load", &format!("settle-{reference}"), &cmd)
                    .await
                    .is_ok()
                {
                    acked.lock().unwrap().push((reference, 50));
                }
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut csv = String::from("external_ref,currency,amount\n");
    let mut lines = acked.lock().unwrap().clone();
    lines.sort();
    for (reference, amount) in &lines {
        writeln!(csv, "{reference},USD,{amount}").unwrap();
    }
    std::fs::write(statement_path, csv).expect("write statement");

    let inv = ledger.invariants().await.unwrap();
    let mut total = 0;
    for s in sources.iter().chain(&dests) {
        let b = ledger.balance(s).await.unwrap();
        assert!(b >= 0, "{s} is negative: {b}");
        total += b;
    }
    total += ledger.balance(&rail).await.unwrap();
    let ok = inv.holds() && total == FUNDING * SOURCES as i64;
    println!(
        "{{\"posted\":{posted},\"refused\":{refused},\"busy\":{busy},\"settled\":{},\"total\":{total},\"negative_accounts\":{},\"unbalanced\":{},\"debits\":{},\"credits\":{},\"ok\":{ok}}}",
        lines.len(),
        inv.negative_accounts,
        inv.unbalanced_transactions,
        inv.debits,
        inv.credits
    );
    std::process::exit(i32::from(!ok));
}
