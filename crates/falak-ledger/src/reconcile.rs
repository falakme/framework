//! Reconciliation of the ledger against an external statement.
//!
//! A statement is a list of lines `external_ref, currency, amount`, where `amount` is
//! signed from the point of view of the ledger account being reconciled (positive adds
//! to it). The ledger side is every `settle` entry on that account. A line matches when
//! the reference, currency and amount all agree.

use std::collections::BTreeMap;

use falak_contracts::{Error, Result};
use serde::Serialize;

use crate::money::{Currency, checked_add};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    pub external_ref: String,
    pub currency: Currency,
    pub amount: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    pub external_ref: String,
    pub ledger: Line,
    pub statement: Line,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub matched: usize,
    /// On the statement, not in the ledger.
    pub missing_in_ledger: Vec<Line>,
    /// In the ledger, not on the statement.
    pub missing_in_statement: Vec<Line>,
    pub mismatched: Vec<Mismatch>,
}

impl Report {
    /// Number of differences. Zero means the ledger and the statement agree.
    pub fn differences(&self) -> usize {
        self.missing_in_ledger.len() + self.missing_in_statement.len() + self.mismatched.len()
    }

    pub fn is_clean(&self) -> bool {
        self.differences() == 0
    }
}

pub fn reconcile(ledger: &[Line], statement: &[Line]) -> Report {
    let ledger_by_ref: BTreeMap<&str, &Line> = ledger
        .iter()
        .map(|l| (l.external_ref.as_str(), l))
        .collect();
    let statement_by_ref: BTreeMap<&str, &Line> = statement
        .iter()
        .map(|l| (l.external_ref.as_str(), l))
        .collect();
    let mut report = Report::default();
    for (r, s) in &statement_by_ref {
        match ledger_by_ref.get(r) {
            None => report.missing_in_ledger.push((*s).clone()),
            Some(l) if l.amount == s.amount && l.currency == s.currency => report.matched += 1,
            Some(l) => report.mismatched.push(Mismatch {
                external_ref: (*r).to_owned(),
                ledger: (*l).clone(),
                statement: (*s).clone(),
            }),
        }
    }
    for (r, l) in &ledger_by_ref {
        if !statement_by_ref.contains_key(r) {
            report.missing_in_statement.push((*l).clone());
        }
    }
    report
}

/// Net total of lines, with checked arithmetic.
pub fn net(lines: &[Line]) -> Result<i64> {
    lines.iter().try_fold(0i64, |a, l| checked_add(a, l.amount))
}

/// Parse a CSV statement: `external_ref,currency,amount`. A header row beginning
/// `external_ref` is skipped, blank lines are ignored, and a reference may appear only
/// once. There is no quoting: references may not contain commas.
pub fn parse_csv(text: &str) -> Result<Vec<Line>> {
    let mut lines = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (i, raw) in text.lines().enumerate() {
        let row = raw.trim();
        if row.is_empty() || (i == 0 && row.starts_with("external_ref")) {
            continue;
        }
        let bad = |why: &str| {
            Error::invalid_input("statement_bad_line", format!("Line {}: {why}.", i + 1))
        };
        let parts: Vec<&str> = row.split(',').map(str::trim).collect();
        let [external_ref, currency, amount] = parts[..] else {
            return Err(bad("expected external_ref,currency,amount"));
        };
        if external_ref.is_empty() || external_ref.len() > 128 {
            return Err(bad("the reference is empty or too long"));
        }
        let currency = Currency::new(currency).map_err(|_| bad("bad currency"))?;
        let amount: i64 = amount
            .parse()
            .map_err(|_| bad("the amount is not a whole number of minor units"))?;
        if amount == 0 {
            return Err(bad("the amount is zero"));
        }
        if !seen.insert(external_ref.to_owned()) {
            return Err(bad("the reference appears twice"));
        }
        lines.push(Line {
            external_ref: external_ref.to_owned(),
            currency,
            amount,
        });
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(r: &str, a: i64) -> Line {
        Line {
            external_ref: r.into(),
            currency: Currency::new("USD").unwrap(),
            amount: a,
        }
    }

    #[test]
    fn equal_sides_are_clean() {
        let l = vec![line("a", 5), line("b", -7)];
        let r = reconcile(&l, &[line("b", -7), line("a", 5)]);
        assert!(r.is_clean());
        assert_eq!(r.matched, 2);
    }

    #[test]
    fn every_kind_of_difference_is_reported() {
        let ledger = vec![line("a", 5), line("b", 6), line("only_ledger", 1)];
        let statement = vec![line("a", 5), line("b", 7), line("only_bank", 2)];
        let r = reconcile(&ledger, &statement);
        assert_eq!(r.matched, 1);
        assert_eq!(r.mismatched.len(), 1);
        assert_eq!(r.missing_in_ledger[0].external_ref, "only_bank");
        assert_eq!(r.missing_in_statement[0].external_ref, "only_ledger");
        assert_eq!(r.differences(), 3);
    }

    #[test]
    fn csv_round_trip_and_errors() {
        let ok = parse_csv("external_ref,currency,amount\nW1,USD,100\n\nW2,USD,-50\n").unwrap();
        assert_eq!(ok, vec![line("W1", 100), line("W2", -50)]);
        assert_eq!(net(&ok).unwrap(), 50);
        assert!(parse_csv("W1,USD,1.5").is_err());
        assert!(parse_csv("W1,usd,1").is_err());
        assert!(parse_csv("W1,USD,1\nW1,USD,2").is_err());
        assert!(parse_csv("W1,USD").is_err());
        assert!(parse_csv("W1,USD,0").is_err());
    }
}
