# ClarityAI

A document pipeline in three steps: **extract** (`jobs/extract_document.yaml`), **scan for
personal data** (`jobs/scan_pii.yaml`), then summarise with an AI model that only ever sees
pseudonymized text. The document `body` is marked `pii: true`; so is the summary text.

Each job is a container a worker runs (`worker/`). See ARCHITECTURE section 4.9 and
`scripts/smoke/ai.sh`.
