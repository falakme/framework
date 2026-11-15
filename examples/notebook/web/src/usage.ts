// Compiles only if the generated client and the SDK agree. Run `pnpm typecheck`.
import { FalakError } from "@falak/sdk";

import { createClient } from "./falak.generated.ts";

export async function demo(token: string): Promise<void> {
  const api = createClient({ baseUrl: "http://127.0.0.1:8787", token });

  const book = await api.notebooks.create({ title: "Work" });
  const note = await api.notes.create({ title: "Plan", notebook_id: book.id });

  // Changing a note: send its version so a concurrent edit is caught.
  await api.notes.update(note.id, { body: "Ship it" }, { ifMatch: note.version });
  await api.notes.archiveNote(note.id);

  for await (const n of api.notes.all({ filter: { archived: false }, sort: ["-created_at"] })) {
    console.log(n.title);
  }

  try {
    await api.notes.get("00000000-0000-0000-0000-000000000000");
  } catch (e) {
    if (e instanceof FalakError && e.status === 404) return;
    throw e;
  }
}
