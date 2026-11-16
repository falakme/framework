//! The PostgreSQL schema of the ledger.
//!
//! Guarantees that hold even if the application code is wrong:
//!
//! * **Append only.** `UPDATE`, `DELETE` and `TRUNCATE` are revoked from `PUBLIC` and from
//!   the application role, and a trigger refuses them for every other role, the table
//!   owner included. Posted history is corrected only by a reversal.
//! * **Deferred balance constraint.** At commit, every transaction's entries sum to zero
//!   per currency. A transaction that does not balance cannot commit.
//! * **Deferred no-overdraft constraint.** At commit, an account that does not allow a
//!   negative balance is not negative. Under `SERIALIZABLE` this is what stops two
//!   concurrent transfers from spending the same money.
//! * **Currency agreement.** An entry's currency equals its account's and its
//!   transaction's, by foreign key.
//! * **One reversal per transaction, one transaction per external reference,** by unique
//!   indexes.
//! * **Idempotency.** `ledger_idempotency` maps a caller's key to the transaction it
//!   produced and a hash of the request, so a retry returns the same result and a key
//!   reused for a different request is refused.

use falak_contracts::{Error, Result};

const TABLES: &[&str] = &[
    "ledger_accounts",
    "ledger_transactions",
    "ledger_entries",
    "ledger_idempotency",
    "ledger_statements",
    "ledger_statement_lines",
];

const BODY: &str = r#"
CREATE TABLE IF NOT EXISTS ledger_accounts (
    id             text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    currency       text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    allow_negative boolean NOT NULL DEFAULT false,
    hold_of        text REFERENCES ledger_accounts (id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, currency)
);

CREATE TABLE IF NOT EXISTS ledger_transactions (
    id           uuid PRIMARY KEY,
    kind         text NOT NULL,
    currency     text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    external_ref text,
    reverses     uuid REFERENCES ledger_transactions (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, currency)
);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_external_ref_unique
    ON ledger_transactions (external_ref) WHERE external_ref IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ledger_reversal_unique
    ON ledger_transactions (reverses) WHERE reverses IS NOT NULL;

CREATE TABLE IF NOT EXISTS ledger_entries (
    id         bigserial PRIMARY KEY,
    tx_id      uuid NOT NULL,
    account_id text NOT NULL,
    currency   text NOT NULL,
    amount     bigint NOT NULL CHECK (amount <> 0),
    FOREIGN KEY (tx_id, currency) REFERENCES ledger_transactions (id, currency),
    FOREIGN KEY (account_id, currency) REFERENCES ledger_accounts (id, currency)
);
CREATE INDEX IF NOT EXISTS ledger_entries_account ON ledger_entries (account_id);
CREATE INDEX IF NOT EXISTS ledger_entries_tx ON ledger_entries (tx_id);

CREATE TABLE IF NOT EXISTS ledger_idempotency (
    key          text PRIMARY KEY,
    request_hash text NOT NULL,
    tx_id        uuid NOT NULL REFERENCES ledger_transactions (id)
                      DEFERRABLE INITIALLY DEFERRED,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ledger_statements (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES ledger_accounts (id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ledger_statement_lines (
    statement_id text NOT NULL REFERENCES ledger_statements (id),
    line_no      integer NOT NULL,
    external_ref text NOT NULL,
    currency     text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount       bigint NOT NULL,
    PRIMARY KEY (statement_id, line_no),
    UNIQUE (statement_id, external_ref)
);

CREATE OR REPLACE FUNCTION ledger_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ledger_immutable: % on % is not allowed; post a reversal instead',
        TG_OP, TG_TABLE_NAME USING ERRCODE = '42501';
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ledger_check_balanced() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM ledger_entries WHERE tx_id = NEW.tx_id
               GROUP BY currency HAVING SUM(amount) <> 0) THEN
        RAISE EXCEPTION 'ledger_unbalanced: transaction % does not balance', NEW.tx_id
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ledger_check_funds() RETURNS trigger AS $$
DECLARE
    neg boolean;
    bal numeric;
BEGIN
    IF NEW.amount < 0 THEN
        SELECT allow_negative INTO neg FROM ledger_accounts WHERE id = NEW.account_id;
        IF NOT neg THEN
            SELECT COALESCE(SUM(amount), 0) INTO bal
              FROM ledger_entries WHERE account_id = NEW.account_id;
            IF bal < 0 THEN
                RAISE EXCEPTION 'ledger_insufficient_funds: account % would be negative',
                    NEW.account_id USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_entries_balanced ON ledger_entries;
CREATE CONSTRAINT TRIGGER ledger_entries_balanced
    AFTER INSERT ON ledger_entries DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ledger_check_balanced();

DROP TRIGGER IF EXISTS ledger_entries_funds ON ledger_entries;
CREATE CONSTRAINT TRIGGER ledger_entries_funds
    AFTER INSERT ON ledger_entries DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ledger_check_funds();
"#;

fn immutability() -> String {
    let mut sql = String::new();
    for t in TABLES {
        sql.push_str(&format!(
            "DROP TRIGGER IF EXISTS {t}_immutable_rows ON {t};\n\
             CREATE TRIGGER {t}_immutable_rows BEFORE UPDATE OR DELETE ON {t}\n\
                 FOR EACH ROW EXECUTE FUNCTION ledger_immutable();\n\
             DROP TRIGGER IF EXISTS {t}_immutable_truncate ON {t};\n\
             CREATE TRIGGER {t}_immutable_truncate BEFORE TRUNCATE ON {t}\n\
                 FOR EACH STATEMENT EXECUTE FUNCTION ledger_immutable();\n"
        ));
    }
    sql
}

/// The statements that create the schema. Safe to run again. With `app_role`, the role
/// gets `SELECT` and `INSERT` on the ledger tables and nothing else, so the running
/// application cannot rewrite history even if it is compromised.
pub fn schema_sql(app_role: Option<&str>) -> Result<String> {
    let mut sql = String::from(BODY);
    sql.push_str(&immutability());
    let list = TABLES.join(", ");
    sql.push_str(&format!(
        "REVOKE UPDATE, DELETE, TRUNCATE ON {list} FROM PUBLIC;\n"
    ));
    if let Some(role) = app_role {
        let ok = !role.is_empty()
            && role.len() <= 63
            && role
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && !role.starts_with(|c: char| c.is_ascii_digit());
        if !ok {
            return Err(Error::invalid_input(
                "ledger_bad_role",
                "A role name is lower-case letters, digits and underscores.",
            ));
        }
        sql.push_str(&format!(
            "REVOKE ALL ON {list} FROM {role};\n\
             GRANT SELECT, INSERT ON {list} TO {role};\n\
             GRANT USAGE, SELECT ON SEQUENCE ledger_entries_id_seq TO {role};\n"
        ));
    }
    Ok(sql)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_insert_and_select_only() {
        let sql = schema_sql(Some("falak_app")).unwrap();
        assert!(sql.contains("GRANT SELECT, INSERT ON"));
        assert!(!sql.contains("GRANT UPDATE"));
        assert!(!sql.contains("GRANT ALL"));
        assert!(sql.contains("REVOKE UPDATE, DELETE, TRUNCATE"));
    }

    #[test]
    fn role_name_is_checked() {
        assert!(schema_sql(Some("x; DROP TABLE y")).is_err());
        assert!(schema_sql(Some("")).is_err());
        assert!(schema_sql(None).is_ok());
    }
}
