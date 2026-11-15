# Notebook

The shared test app for Phases 1 and 2. It covers:

* **Ownership:** every notebook and note belongs to the person who created it.
* **Roles:** `admin` can read everything.
* **A relation:** a notebook has many notes; a note belongs to one notebook.
* **Commands:** `archive_note` (idempotent) and `restore_note`.

It declares no `custom` command: a custom command needs interactive transactions,
which D1 does not have, and Notebook must build for SQLite, PostgreSQL and D1 with no
changes. See TASKS.md §6.
