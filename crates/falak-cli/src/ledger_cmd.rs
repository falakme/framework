//! `falak ledger init | import | reconcile` (T8.3).
//!
//! `init` creates the ledger tables. `import` stores an external statement (CSV:
//! `external_ref,currency,amount`, amounts signed from the ledger account's side).
//! `reconcile` compares the stored statement with the ledger's settlements on that
//! account and exits 1 if anything differs, so a scheduler can alert on it.

use std::path::PathBuf;

use falak_ledger::{Ledger, reconcile::parse_csv};

use crate::args::Command;

pub struct Options {
    pub database_url: Option<String>,
    pub statement: Option<PathBuf>,
    pub statement_id: Option<String>,
    pub account: Option<String>,
    pub app_role: Option<String>,
}

pub fn run(command: Command, o: &Options) -> Result<u8, String> {
    let url = o
        .database_url
        .clone()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .ok_or("the ledger needs `--database-url` or DATABASE_URL (PostgreSQL)")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    runtime.block_on(async {
        let ledger = Ledger::connect(&url, 2).await.map_err(|e| e.to_string())?;
        match command {
            Command::LedgerInit => {
                ledger
                    .install_schema(o.app_role.as_deref())
                    .await
                    .map_err(|e| e.to_string())?;
                println!("ledger schema installed");
                Ok(0)
            }
            Command::LedgerImport => {
                let path = o
                    .statement
                    .as_ref()
                    .ok_or("`--statement <csv>` is required")?;
                let id = o
                    .statement_id
                    .as_deref()
                    .ok_or("`--statement-id <id>` is required")?;
                let account = o
                    .account
                    .as_deref()
                    .ok_or("`--ledger-account <account>` is required")?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
                let lines = parse_csv(&text).map_err(|e| e.to_string())?;
                ledger
                    .import_statement(id, account, &lines)
                    .await
                    .map_err(|e| e.to_string())?;
                println!("imported statement `{id}`: {} line(s)", lines.len());
                Ok(0)
            }
            _ => {
                let id = o
                    .statement_id
                    .as_deref()
                    .ok_or("`--statement-id <id>` is required")?;
                let report = ledger.reconcile(id).await.map_err(|e| e.to_string())?;
                println!("matched: {}", report.matched);
                for l in &report.missing_in_ledger {
                    println!(
                        "on the statement, not in the ledger: {} {} {}",
                        l.external_ref, l.currency, l.amount
                    );
                }
                for l in &report.missing_in_statement {
                    println!(
                        "in the ledger, not on the statement: {} {} {}",
                        l.external_ref, l.currency, l.amount
                    );
                }
                for m in &report.mismatched {
                    println!(
                        "amount differs for {}: ledger {} {}, statement {} {}",
                        m.external_ref,
                        m.ledger.currency,
                        m.ledger.amount,
                        m.statement.currency,
                        m.statement.amount
                    );
                }
                println!("differences: {}", report.differences());
                Ok(u8::from(!report.is_clean()))
            }
        }
    })
}
