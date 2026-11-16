# DataMan

Where a team keeps track of its data: which datasets exist, how sensitive they are, what recovery objectives each one has, when it was last backed up, and whether a restore has actually been tried.

| Entity | What it holds | Who owns a row | Who else can read it |
|---|---|---|---|
| dataset | name, classification, personal data or not, retention, RPO and RTO in minutes | its custodian | people with the role `auditor` |
| backup_run | one backup of a dataset: when, kind, size, where, verified or not | its custodian | auditors |
| restore_drill | one recovery drill: when, seconds taken, seconds of data lost, passed or not | its custodian | auditors |

Commands: `verify_backup` marks a backup as verified; `pass_drill` marks a drill as passed.

Defaults are the framework's objectives: RPO 5 minutes, RTO 60 minutes. A drill passes when `seconds_taken` is within the dataset's RTO and `seconds_data_lost` is within its RPO; `scripts/smoke/dr.sh` prints exactly those two numbers, and a custodian records them as a `restore_drill`.

```
falak serve examples/dataman
```

Studio reads the schema from the running app and gives custodians and auditors forms and lists for all three entities with no extra code. The **Observatory** tab in Studio (service-level objectives, the audit chain and break-glass requests) is Office's own view and is shown to Office administrators next to the app tabs.
