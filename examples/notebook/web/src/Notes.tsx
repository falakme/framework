import { type FormEvent, useCallback, useEffect, useState } from "react";

import { api, describe } from "./api.ts";
import type { Note, Notebook } from "./falak.generated.ts";

export function Notes({ notebook }: { notebook: Notebook }) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [showArchived, setShowArchived] = useState(false);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    try {
      const page = await api.notes.list({
        filter: { notebook_id: notebook.id, archived: showArchived },
        sort: ["-created_at"],
        pageSize: 100,
      });
      setNotes(page.data);
      setError(undefined);
    } catch (e) {
      setError(describe(e));
    }
  }, [notebook.id, showArchived]);

  useEffect(() => {
    void load();
  }, [load]);

  /** Run an action, then reload so the list matches the server. */
  async function act(action: () => Promise<unknown>) {
    try {
      await action();
      setError(undefined);
    } catch (e) {
      setError(describe(e));
    }
    await load();
  }

  function add(e: FormEvent) {
    e.preventDefault();
    const text = title.trim();
    if (!text) return;
    setTitle("");
    void act(() => api.notes.create({ title: text, notebook_id: notebook.id }));
  }

  return (
    <section className="notes">
      <header>
        <h2>{notebook.title}</h2>
        <label className="check">
          <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />
          Show archived
        </label>
      </header>
      <form className="row" onSubmit={add}>
        <input
          aria-label="New note title"
          placeholder="New note"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={200}
        />
        <button type="submit">Add</button>
      </form>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <ul>
        {notes.map((note) => (
          <li key={`${note.id}:${note.version}`} className="card">
            <input
              aria-label="Title"
              className="title"
              defaultValue={note.title}
              maxLength={200}
              onBlur={(e) => {
                const value = e.target.value.trim();
                if (value && value !== note.title) {
                  void act(() => api.notes.update(note.id, { title: value }, { ifMatch: note.version }));
                }
              }}
            />
            <textarea
              aria-label="Body"
              defaultValue={note.body ?? ""}
              rows={3}
              onBlur={(e) => {
                if (e.target.value !== (note.body ?? "")) {
                  void act(() => api.notes.update(note.id, { body: e.target.value }, { ifMatch: note.version }));
                }
              }}
            />
            <div className="row">
              {showArchived ? (
                <button type="button" onClick={() => void act(() => api.notes.restoreNote(note.id))}>
                  Restore
                </button>
              ) : (
                <button type="button" onClick={() => void act(() => api.notes.archiveNote(note.id))}>
                  Archive
                </button>
              )}
              <button
                type="button"
                className="danger"
                onClick={() => void act(() => api.notes.delete(note.id, { ifMatch: note.version }))}
              >
                Delete
              </button>
            </div>
          </li>
        ))}
      </ul>
      {notes.length === 0 && !error && (
        <p className="hint">{showArchived ? "No archived notes." : "No notes yet."}</p>
      )}
    </section>
  );
}
