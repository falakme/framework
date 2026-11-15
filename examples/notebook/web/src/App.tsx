import { type FormEvent, useCallback, useEffect, useState, useSyncExternalStore } from "react";

import { api, describe, session } from "./api.ts";
import { AuthForm } from "./AuthForm.tsx";
import type { Notebook } from "./falak.generated.ts";
import { Notes } from "./Notes.tsx";

export function App() {
  const signedIn = useSyncExternalStore(
    (listener) => session.subscribe(listener),
    () => session.signedIn,
  );
  return signedIn ? <Home /> : <AuthForm />;
}

function Home() {
  const [books, setBooks] = useState<Notebook[]>([]);
  const [selected, setSelected] = useState<string>();
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    try {
      const page = await api.notebooks.list({ sort: ["title"], pageSize: 100 });
      setBooks(page.data);
      setSelected((current) => current ?? page.data[0]?.id);
      setError(undefined);
    } catch (e) {
      setError(describe(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function add(e: FormEvent) {
    e.preventDefault();
    const text = title.trim();
    if (!text) return;
    setTitle("");
    try {
      const book = await api.notebooks.create({ title: text });
      setSelected(book.id);
      await load();
    } catch (err) {
      setError(describe(err));
    }
  }

  const current = books.find((b) => b.id === selected);

  return (
    <div className="layout">
      <aside>
        <h1>Notebooks</h1>
        <ul>
          {books.map((b) => (
            <li key={b.id}>
              <button type="button" className={b.id === selected ? "active" : ""} onClick={() => setSelected(b.id)}>
                {b.title}
              </button>
            </li>
          ))}
        </ul>
        <form className="row" onSubmit={add}>
          <input
            aria-label="New notebook title"
            placeholder="New notebook"
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
        <button type="button" className="link" onClick={() => void session.logOut()}>
          Log out
        </button>
      </aside>
      <main>
        {current ? <Notes key={current.id} notebook={current} /> : <p className="hint">Create a notebook to start.</p>}
      </main>
    </div>
  );
}
