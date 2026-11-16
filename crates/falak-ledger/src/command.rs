//! Ledger commands and their planning.
//!
//! A [`Command`] is turned into a [`Plan`]: balanced postings, plus any hold account to
//! create. Planning is pure. It reads the [`Facts`] the executor loaded (account
//! currencies, hold balances, the entries of a transaction to reverse) and never touches
//! a database, so every rule here is unit tested without one.
//!
//! The database enforces the same rules again (see `schema`): a plan that is wrong
//! cannot commit.
//!
//! | Command | Effect |
//! | :-- | :-- |
//! | `transfer` | move `amount` from one account to another, same currency |
//! | `reserve` | move `amount` from an account into a new hold account `hold` |
//! | `capture` | move `amount` (at most the hold's balance) from the hold to a destination |
//! | `release` | return the hold's whole remaining balance to the account it came from |
//! | `reverse` | post the exact opposite of an earlier transaction, once |
//! | `settle` | move funds to a settlement account and tag the transaction with the external reference that a bank statement will carry |

use std::collections::HashMap;

use falak_contracts::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::money::{Currency, account_id, checked_add, checked_neg, positive};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    Transfer {
        from: String,
        to: String,
        amount: i64,
        currency: Currency,
    },
    Reserve {
        hold: String,
        account: String,
        amount: i64,
        currency: Currency,
    },
    Capture {
        hold: String,
        to: String,
        amount: i64,
    },
    Release {
        hold: String,
    },
    Reverse {
        tx: Uuid,
    },
    Settle {
        from: String,
        settlement: String,
        amount: i64,
        currency: Currency,
        external_ref: String,
    },
}

/// One signed line of a transaction. Negative takes from the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    pub account: String,
    pub amount: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub id: String,
    pub currency: Currency,
    pub hold_of: Option<String>,
}

/// What the executor will write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub kind: &'static str,
    pub currency: Currency,
    pub postings: Vec<Posting>,
    pub new_accounts: Vec<NewAccount>,
    pub external_ref: Option<String>,
    pub reverses: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub currency: Currency,
    pub hold_of: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInfo {
    pub kind: String,
    pub currency: Currency,
    pub entries: Vec<Posting>,
}

/// What a command needs to know, loaded by the executor inside its transaction.
#[derive(Debug, Default, Clone)]
pub struct Facts {
    pub accounts: HashMap<String, AccountInfo>,
    pub balances: HashMap<String, i64>,
    pub txs: HashMap<Uuid, TxInfo>,
}

impl Facts {
    fn account(&self, id: &str) -> Result<&AccountInfo> {
        self.accounts.get(id).ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "ledger_unknown_account",
                "An account in the command does not exist.",
            )
        })
    }

    fn balance(&self, id: &str) -> i64 {
        self.balances.get(id).copied().unwrap_or(0)
    }

    fn hold(&self, id: &str) -> Result<(&AccountInfo, &str)> {
        let info = self.account(id)?;
        let source = info.hold_of.as_deref().ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "ledger_unknown_hold",
                "The hold does not exist.",
            )
        })?;
        Ok((info, source))
    }
}

/// The accounts and transaction a command will read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Needs {
    pub accounts: Vec<String>,
    pub tx: Option<Uuid>,
}

fn insufficient() -> Error {
    Error::new(
        ErrorKind::Conflict,
        "ledger_insufficient_funds",
        "The account does not hold enough to cover this.",
    )
}

fn currency_mismatch() -> Error {
    Error::invalid_input(
        "ledger_currency_mismatch",
        "The accounts and the amount must all use the same currency.",
    )
}

impl Command {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Transfer { .. } => "transfer",
            Self::Reserve { .. } => "reserve",
            Self::Capture { .. } => "capture",
            Self::Release { .. } => "release",
            Self::Reverse { .. } => "reverse",
            Self::Settle { .. } => "settle",
        }
    }

    /// Stable bytes of the command, used for the idempotency request hash and, by the
    /// Tier 3 controls, as the transaction hash a person approves.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Derived `Serialize` writes fields in declaration order, so this is stable.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Lower-case hex SHA-256 of [`Self::canonical_bytes`].
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn needs(&self) -> Needs {
        match self {
            Self::Transfer { from, to, .. } => Needs {
                accounts: vec![from.clone(), to.clone()],
                tx: None,
            },
            Self::Reserve { hold, account, .. } => Needs {
                accounts: vec![hold.clone(), account.clone()],
                tx: None,
            },
            Self::Capture { hold, to, .. } => Needs {
                accounts: vec![hold.clone(), to.clone()],
                tx: None,
            },
            Self::Release { hold } => Needs {
                accounts: vec![hold.clone()],
                tx: None,
            },
            Self::Reverse { tx } => Needs {
                accounts: vec![],
                tx: Some(*tx),
            },
            Self::Settle {
                from, settlement, ..
            } => Needs {
                accounts: vec![from.clone(), settlement.clone()],
                tx: None,
            },
        }
    }

    /// Check the command's own shape, before anything is read.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Transfer {
                from, to, amount, ..
            } => {
                account_id(from)?;
                account_id(to)?;
                positive(*amount)?;
                if from == to {
                    return Err(Error::invalid_input(
                        "ledger_same_account",
                        "The two accounts must differ.",
                    ));
                }
            }
            Self::Reserve {
                hold,
                account,
                amount,
                ..
            } => {
                account_id(hold)?;
                account_id(account)?;
                positive(*amount)?;
                if hold == account {
                    return Err(Error::invalid_input(
                        "ledger_same_account",
                        "The hold and the account must differ.",
                    ));
                }
            }
            Self::Capture { hold, to, amount } => {
                account_id(hold)?;
                account_id(to)?;
                positive(*amount)?;
            }
            Self::Release { hold } => account_id(hold)?,
            Self::Reverse { .. } => {}
            Self::Settle {
                from,
                settlement,
                amount,
                external_ref,
                ..
            } => {
                account_id(from)?;
                account_id(settlement)?;
                positive(*amount)?;
                if from == settlement {
                    return Err(Error::invalid_input(
                        "ledger_same_account",
                        "The two accounts must differ.",
                    ));
                }
                if external_ref.is_empty() || external_ref.len() > 128 {
                    return Err(Error::invalid_input(
                        "ledger_bad_reference",
                        "An external reference is 1 to 128 characters.",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Turn the command into balanced postings.
    pub fn plan(&self, facts: &Facts) -> Result<Plan> {
        self.validate()?;
        let plan = match self {
            Self::Transfer {
                from,
                to,
                amount,
                currency,
            } => {
                same_currency(facts, &[from, to], *currency)?;
                plain("transfer", *currency, from, to, *amount, None)?
            }
            Self::Settle {
                from,
                settlement,
                amount,
                currency,
                external_ref,
            } => {
                same_currency(facts, &[from, settlement], *currency)?;
                plain(
                    "settle",
                    *currency,
                    from,
                    settlement,
                    *amount,
                    Some(external_ref.clone()),
                )?
            }
            Self::Reserve {
                hold,
                account,
                amount,
                currency,
            } => {
                same_currency(facts, &[account], *currency)?;
                if facts.accounts.contains_key(hold) {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "ledger_hold_exists",
                        "A hold with this id already exists.",
                    ));
                }
                let mut p = plain("reserve", *currency, account, hold, *amount, None)?;
                p.new_accounts.push(NewAccount {
                    id: hold.clone(),
                    currency: *currency,
                    hold_of: Some(account.clone()),
                });
                p
            }
            Self::Capture { hold, to, amount } => {
                let (info, _) = facts.hold(hold)?;
                let currency = info.currency;
                same_currency(facts, &[to], currency)?;
                if facts.balance(hold) < *amount {
                    return Err(insufficient());
                }
                plain("capture", currency, hold, to, *amount, None)?
            }
            Self::Release { hold } => {
                let (info, source) = facts.hold(hold)?;
                let remaining = facts.balance(hold);
                if remaining <= 0 {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "ledger_hold_empty",
                        "The hold has nothing left to release.",
                    ));
                }
                plain("release", info.currency, hold, source, remaining, None)?
            }
            Self::Reverse { tx } => {
                let original = facts.txs.get(tx).ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        "ledger_unknown_transaction",
                        "The transaction does not exist.",
                    )
                })?;
                if original.kind == "reverse" {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "ledger_cannot_reverse_reversal",
                        "A reversal cannot be reversed. Post a new transfer instead.",
                    ));
                }
                let postings = original
                    .entries
                    .iter()
                    .map(|e| {
                        Ok(Posting {
                            account: e.account.clone(),
                            amount: checked_neg(e.amount)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Plan {
                    kind: "reverse",
                    currency: original.currency,
                    postings,
                    new_accounts: vec![],
                    external_ref: None,
                    reverses: Some(*tx),
                }
            }
        };
        plan.check_balanced()?;
        Ok(plan)
    }
}

fn same_currency(facts: &Facts, ids: &[&String], currency: Currency) -> Result<()> {
    for id in ids {
        if facts.account(id)?.currency != currency {
            return Err(currency_mismatch());
        }
    }
    Ok(())
}

fn plain(
    kind: &'static str,
    currency: Currency,
    from: &str,
    to: &str,
    amount: i64,
    external_ref: Option<String>,
) -> Result<Plan> {
    Ok(Plan {
        kind,
        currency,
        postings: vec![
            Posting {
                account: from.to_owned(),
                amount: checked_neg(amount)?,
            },
            Posting {
                account: to.to_owned(),
                amount,
            },
        ],
        new_accounts: vec![],
        external_ref,
        reverses: None,
    })
}

impl Plan {
    /// Debits equal credits, with checked arithmetic, and no zero or empty posting.
    pub fn check_balanced(&self) -> Result<()> {
        if self.postings.len() < 2 || self.postings.iter().any(|p| p.amount == 0) {
            return Err(Error::internal("plan has fewer than two non-zero postings"));
        }
        let mut sum = 0i64;
        for p in &self.postings {
            sum = checked_add(sum, p.amount)?;
        }
        if sum != 0 {
            return Err(Error::internal("plan does not balance"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd() -> Currency {
        Currency::new("USD").unwrap()
    }

    fn eur() -> Currency {
        Currency::new("EUR").unwrap()
    }

    fn facts() -> Facts {
        let mut f = Facts::default();
        for (id, c) in [("alice", usd()), ("bob", usd()), ("euro", eur())] {
            f.accounts.insert(
                id.into(),
                AccountInfo {
                    currency: c,
                    hold_of: None,
                },
            );
        }
        f.accounts.insert(
            "h1".into(),
            AccountInfo {
                currency: usd(),
                hold_of: Some("alice".into()),
            },
        );
        f.balances.insert("h1".into(), 700);
        f
    }

    fn transfer(from: &str, to: &str, amount: i64, c: Currency) -> Command {
        Command::Transfer {
            from: from.into(),
            to: to.into(),
            amount,
            currency: c,
        }
    }

    #[test]
    fn transfer_balances() {
        let p = transfer("alice", "bob", 500, usd()).plan(&facts()).unwrap();
        assert_eq!(p.postings[0].amount, -500);
        assert_eq!(p.postings[1].amount, 500);
        p.check_balanced().unwrap();
    }

    #[test]
    fn rejects_bad_amounts_and_same_account() {
        let f = facts();
        assert!(transfer("alice", "bob", 0, usd()).plan(&f).is_err());
        assert!(transfer("alice", "bob", -1, usd()).plan(&f).is_err());
        assert!(transfer("alice", "alice", 1, usd()).plan(&f).is_err());
    }

    #[test]
    fn currency_is_checked_against_both_accounts() {
        let f = facts();
        let e = transfer("alice", "euro", 5, usd()).plan(&f).unwrap_err();
        assert_eq!(e.code(), "ledger_currency_mismatch");
        let e = transfer("alice", "bob", 5, eur()).plan(&f).unwrap_err();
        assert_eq!(e.code(), "ledger_currency_mismatch");
        let e = transfer("alice", "ghost", 5, usd()).plan(&f).unwrap_err();
        assert_eq!(e.code(), "ledger_unknown_account");
    }

    #[test]
    fn reserve_creates_the_hold() {
        let p = Command::Reserve {
            hold: "h2".into(),
            account: "alice".into(),
            amount: 300,
            currency: usd(),
        }
        .plan(&facts())
        .unwrap();
        assert_eq!(p.new_accounts[0].hold_of.as_deref(), Some("alice"));
        assert_eq!(p.postings[1].account, "h2");
        let again = Command::Reserve {
            hold: "h1".into(),
            account: "alice".into(),
            amount: 1,
            currency: usd(),
        }
        .plan(&facts());
        assert_eq!(again.unwrap_err().code(), "ledger_hold_exists");
    }

    #[test]
    fn capture_is_limited_to_the_hold() {
        let f = facts();
        let ok = Command::Capture {
            hold: "h1".into(),
            to: "bob".into(),
            amount: 700,
        }
        .plan(&f)
        .unwrap();
        assert_eq!(ok.postings[0].account, "h1");
        let over = Command::Capture {
            hold: "h1".into(),
            to: "bob".into(),
            amount: 701,
        }
        .plan(&f);
        assert_eq!(over.unwrap_err().code(), "ledger_insufficient_funds");
        let wrong = Command::Capture {
            hold: "h1".into(),
            to: "euro".into(),
            amount: 1,
        }
        .plan(&f);
        assert_eq!(wrong.unwrap_err().code(), "ledger_currency_mismatch");
        let not_hold = Command::Capture {
            hold: "bob".into(),
            to: "alice".into(),
            amount: 1,
        }
        .plan(&f);
        assert_eq!(not_hold.unwrap_err().code(), "ledger_unknown_hold");
    }

    #[test]
    fn release_returns_the_remainder_to_the_source() {
        let p = Command::Release { hold: "h1".into() }
            .plan(&facts())
            .unwrap();
        assert_eq!(p.postings[1].account, "alice");
        assert_eq!(p.postings[1].amount, 700);
        let mut empty = facts();
        empty.balances.insert("h1".into(), 0);
        let e = Command::Release { hold: "h1".into() }.plan(&empty);
        assert_eq!(e.unwrap_err().code(), "ledger_hold_empty");
    }

    #[test]
    fn reverse_negates_exactly_and_not_twice_over() {
        let id = Uuid::new_v4();
        let mut f = facts();
        f.txs.insert(
            id,
            TxInfo {
                kind: "transfer".into(),
                currency: usd(),
                entries: vec![
                    Posting {
                        account: "alice".into(),
                        amount: -40,
                    },
                    Posting {
                        account: "bob".into(),
                        amount: 40,
                    },
                ],
            },
        );
        let p = Command::Reverse { tx: id }.plan(&f).unwrap();
        assert_eq!(p.reverses, Some(id));
        assert_eq!(p.postings[0].amount, 40);
        assert_eq!(p.postings[1].amount, -40);
        let rid = Uuid::new_v4();
        f.txs.insert(
            rid,
            TxInfo {
                kind: "reverse".into(),
                currency: usd(),
                entries: vec![],
            },
        );
        let e = Command::Reverse { tx: rid }.plan(&f).unwrap_err();
        assert_eq!(e.code(), "ledger_cannot_reverse_reversal");
        let e = Command::Reverse { tx: Uuid::new_v4() }
            .plan(&f)
            .unwrap_err();
        assert_eq!(e.code(), "ledger_unknown_transaction");
    }

    #[test]
    fn settle_carries_the_external_reference() {
        let mut f = facts();
        f.accounts.insert(
            "bank".into(),
            AccountInfo {
                currency: usd(),
                hold_of: None,
            },
        );
        let p = Command::Settle {
            from: "alice".into(),
            settlement: "bank".into(),
            amount: 9,
            currency: usd(),
            external_ref: "WIRE-1".into(),
        }
        .plan(&f)
        .unwrap();
        assert_eq!(p.external_ref.as_deref(), Some("WIRE-1"));
        assert_eq!(p.kind, "settle");
    }

    #[test]
    fn extreme_amounts_do_not_wrap() {
        let mut f = facts();
        f.txs.insert(
            Uuid::nil(),
            TxInfo {
                kind: "transfer".into(),
                currency: usd(),
                entries: vec![
                    Posting {
                        account: "alice".into(),
                        amount: i64::MIN,
                    },
                    Posting {
                        account: "bob".into(),
                        amount: i64::MAX,
                    },
                ],
            },
        );
        let e = Command::Reverse { tx: Uuid::nil() }.plan(&f).unwrap_err();
        assert_eq!(e.code(), "ledger_overflow");
        assert!(
            transfer("alice", "bob", i64::MAX, usd())
                .plan(&facts())
                .is_ok()
        );
    }

    #[test]
    fn hash_is_stable_and_distinguishes_commands() {
        let a = transfer("alice", "bob", 5, usd());
        assert_eq!(a.hash(), a.clone().hash());
        assert_ne!(a.hash(), transfer("alice", "bob", 6, usd()).hash());
        assert_eq!(a.hash().len(), 64);
    }
}
