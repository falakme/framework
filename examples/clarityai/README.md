# ClarityAI (test fixture)

A tiny document app that `scripts/smoke/ai.sh` and the `falak-ai` tests use. `document.body`
and `summary.text` carry the `pii: true` schema annotation, so the MCP projection leaves them
out of what an agent reads. It has no jobs or workers: it only shows an AI tool working with
a Falak app safely (calling user's policies, read-only by default, approval for writes).
