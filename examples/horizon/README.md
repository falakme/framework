# Horizon

Wallets and payments for the other apps. Horizon owns the money: every wallet is a
ledger account in `falak-ledger`, and a payment is a hold on it.

| Entity | Who owns a row | Who else can read it |
|---|---|---|
| wallet | its owner | `auditor` role |
| payment | the payer | `auditor` role |

It declares `trust_tier: high_assurance` (Tier 3, `falak-auth::tier3`): a sensitive
command needs a sender-constrained token, an online session check, a passkey assertion
over the transaction hash and, if configured, dual approval.

## Federated commands

Other apps call these through Falak Office. Each is a handler over a `falak-ledger`
command and runs under an idempotency key.

| Command | Ledger command | Undone by |
|---|---|---|
| `payment_reserve` | `reserve`: move funds from the wallet into a hold | `payment_release` |
| `payment_capture` | `capture`: move (part of) the hold to the merchant | `payment_reverse` |
| `payment_release` | `release`: return what is left of the hold | |
| `payment_reverse` | `reverse`: post the opposite of a transaction, once | |

## Checkout

A storefront checkout is a saga (`falak_ledger::saga`): reserve funds, place the order,
capture funds. If the order fails the hold is released; if the capture fails the order is
cancelled and then the hold is released. Academy's checkout creates an `enrollment`;
GardenX's (Phase 5) places an order. `academy_checkout` and `gardenx_checkout` build the
step lists, and `HorizonParticipant` runs the Horizon steps on the ledger.

**Status.** The YAML declares the contract. The handlers named above are not wired into
the runtime yet, and sagas are not persisted across a crash until the Phase 5 events
land. Not production ready, and no legal advice has been taken (TASKS.md section 4).
