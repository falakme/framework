// The signed-in state: tokens, refreshing, and sign-out.
//
// * The short-lived access token stays in memory only.
// * The refresh token is kept in `sessionStorage` (gone when the tab closes), so a
//   reload does not sign the person out. This is a demo choice; a production app that
//   handles sensitive data should keep it in an HttpOnly cookie set by a server.
// * Several calls at once share one refresh. A refresh token works once, so two
//   refreshes in parallel would end the session.

import { FalakError } from "@falak/sdk";

export interface Tokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface Storage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface SessionOptions {
  fetch?: typeof fetch;
  storage?: Storage;
  /** Milliseconds since the epoch. Replaceable for tests. */
  now?: () => number;
  /** Refresh this many seconds before the access token expires. */
  skewSeconds?: number;
}

const KEY = "falak.refresh";

export class Session {
  #fetch: typeof fetch;
  #storage: Storage | undefined;
  #now: () => number;
  #skew: number;
  #access: string | undefined;
  #expiresAt = 0;
  #refreshing: Promise<string | undefined> | undefined;
  #listeners = new Set<() => void>();

  constructor(options: SessionOptions = {}) {
    this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#storage = options.storage ?? (typeof sessionStorage === "undefined" ? undefined : sessionStorage);
    this.#now = options.now ?? Date.now;
    this.#skew = options.skewSeconds ?? 30;
  }

  /** True when there is a refresh token or a live access token. */
  get signedIn(): boolean {
    return this.#access !== undefined || this.#storage?.getItem(KEY) != null;
  }

  /** Call `listener` whenever the signed-in state changes. Returns a function that stops it. */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #changed(): void {
    for (const l of this.#listeners) l();
  }

  async #post(path: string, body: unknown): Promise<Response> {
    return this.#fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  async #problem(response: Response): Promise<FalakError> {
    let problem = {};
    try {
      problem = await response.json();
    } catch {
      // Not JSON: keep the status.
    }
    return new FalakError(response.status, problem);
  }

  #store(tokens: Tokens): void {
    this.#access = tokens.access_token;
    this.#expiresAt = this.#now() + tokens.expires_in * 1000;
    this.#storage?.setItem(KEY, tokens.refresh_token);
  }

  #clear(): void {
    this.#access = undefined;
    this.#expiresAt = 0;
    this.#storage?.removeItem(KEY);
  }

  async signUp(email: string, password: string): Promise<void> {
    const res = await this.#post("/v1/auth/signup", { email, password });
    if (!res.ok) throw await this.#problem(res);
    await this.logIn(email, password);
  }

  async logIn(email: string, password: string): Promise<void> {
    const res = await this.#post("/v1/auth/login", { email, password });
    if (!res.ok) throw await this.#problem(res);
    this.#store((await res.json()) as Tokens);
    this.#changed();
  }

  async logOut(): Promise<void> {
    const refresh = this.#storage?.getItem(KEY);
    this.#clear();
    this.#changed();
    if (refresh) {
      try {
        await this.#post("/v1/auth/logout", { refresh_token: refresh });
      } catch {
        // Signed out here either way; the server session ends when it expires.
      }
    }
  }

  /**
   * A valid access token, refreshing first if it is close to expiring. `undefined` if
   * the person is signed out (and the signed-out state is announced).
   */
  async accessToken(): Promise<string | undefined> {
    if (this.#access !== undefined && this.#now() < this.#expiresAt - this.#skew * 1000) {
      return this.#access;
    }
    this.#refreshing ??= this.#refresh().finally(() => {
      this.#refreshing = undefined;
    });
    return this.#refreshing;
  }

  async #refresh(): Promise<string | undefined> {
    const refresh = this.#storage?.getItem(KEY);
    if (!refresh) {
      this.#clear();
      this.#changed();
      return undefined;
    }
    let res: Response;
    try {
      res = await this.#post("/v1/auth/refresh", { refresh_token: refresh });
    } catch {
      // Network trouble is not a sign-out. Keep the tokens and let the request fail.
      return this.#access;
    }
    if (!res.ok) {
      if (res.status === 401 || res.status === 400) {
        this.#clear();
        this.#changed();
        return undefined;
      }
      return this.#access;
    }
    this.#store((await res.json()) as Tokens);
    return this.#access;
  }
}
