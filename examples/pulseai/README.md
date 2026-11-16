# PulseAI

Team pulse surveys. An answer's `comment` is marked `pii: true`, and `answer` rows are
readable only by the person who wrote them, so a manager sees the `digest`, not the people.
The `summarize_pulse` job (see `worker/summarize.py`) receives scores and comments with no
identifiers. Its contract lists no egress host: the job has no network at all.
