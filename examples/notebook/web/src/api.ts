import { FalakError } from "@falak/sdk";

import { createClient } from "./falak.generated.ts";
import { Session } from "./session.ts";

export const session = new Session();

/** The generated client. It asks the session for a fresh token on every request. */
export const api = createClient({
  baseUrl: "",
  token: async () => (await session.accessToken()) ?? "",
});

/** A message for a person, from whatever went wrong. */
export function describe(error: unknown): string {
  if (error instanceof FalakError) {
    if (error.isVersionConflict) return "Someone changed this first. It has been reloaded; try again.";
    const fields = Object.entries(error.fieldErrors());
    if (fields.length > 0) return fields.map(([name, reason]) => `${name}: ${reason}`).join("; ");
    return error.detail;
  }
  return error instanceof Error ? error.message : "Something went wrong.";
}
