# BlockBanking

A bank's customer accounts, transfer orders and daily statement reconciliation on the
Falak ledger (`falak-ledger`).

| Entity | Who owns a row | Who else can read it |
|---|---|---|
| customer_account | the customer | `teller` (opens), `auditor` |
| transfer_order | the customer | `approver` (approves), `auditor` |
| statement_import | the importer | `reconciler`, `auditor` |

A transfer order is created by the customer, approved by an `approver` (`approve_transfer`),
then posted by `post_transfer`, which runs `falak_ledger::Command::Transfer` under
`SERIALIZABLE`. The app is `high_assurance` (Tier 3): the post needs the controls in
`falak-auth::tier3`, with the transaction hash as the passkey challenge and dual approval.

Reconciliation: `falak ledger import --statement bank.csv --statement-id 2026-11-16
--ledger-account rail`, then `falak ledger reconcile --statement-id 2026-11-16` (exit code 1
if anything differs).

**Status.** The YAML declares the contract; the handlers are not wired into the runtime.
Not production ready. Legal advice on running a bank-like service has not been taken
(TASKS.md section 4).
