# ClarityAI

A document pipeline in three steps: **extract** (`jobs/extract_document.yaml`), **scan for
personal data** (`jobs/scan_pii.yaml`), then summarise with an AI model that only ever sees
pseudonymized text. The document `body` is marked `pii: true`; so is the summary text.

Each job is a container a worker runs (`worker/`). See ARCHITECTURE section 4.9 and
`scripts/smoke/ai.sh`.

## PII shield

`shield/` is a page that shows a document three ways: as written with personal data
highlighted, as a model sees it (stable tokens only) and blocked out for sharing. Serve it
with `python3 -m http.server -d shield` and open `index.html`; "Try a sample" needs no app.
Test it with `node --test shield/shield.test.mjs`.
