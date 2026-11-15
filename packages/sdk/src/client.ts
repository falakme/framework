import { FalakError, type Problem } from "./errors.ts";
import { buildQuery, type ListOptions } from "./query.ts";

export interface PageMeta {
  page_size: number;
  has_more: boolean;
  next_cursor: string | null;
  prev_cursor: string | null;
}

export interface Page<T> {
  data: T[];
  meta: PageMeta;
}

export type TokenSource = string | (() => string | Promise<string>);

export interface ClientOptions {
  /** Where the API lives, for example `https://api.example.com` or `/`. */
  baseUrl: string;
  /** A bearer token, or a function that returns a fresh one for each request. */
  token?: TokenSource;
  /** Replace `fetch`, for tests or a custom agent. */
  fetch?: typeof fetch;
  /** How many times to retry a request that is safe to repeat. Default 2. */
  maxRetries?: number;
  /** Make idempotency keys. Default: `crypto.randomUUID`. */
  newIdempotencyKey?: () => string;
}

export interface RequestOptions {
  query?: string;
  body?: unknown;
  /** A version number or an ETag, sent as `If-Match`. */
  ifMatch?: number | string;
  /** Send an `Idempotency-Key` (default true for writes). Retries reuse the same key. */
  idempotent?: boolean;
  signal?: AbortSignal;
}

export interface Reply<T> {
  data: T;
  etag: string | null;
  status: number;
}

const WRITES = new Set(["POST", "PATCH", "PUT", "DELETE"]);
const RETRY_STATUS = new Set([429, 503, 504]);

/** Turn a version number into the weak ETag the API uses. */
export function etagFor(version: number | string): string {
  return typeof version === "number" ? `W/"${version}"` : version;
}

/** The HTTP layer shared by every generated client. */
export class FalakClient {
  readonly baseUrl: string;
  readonly #token: TokenSource | undefined;
  readonly #fetch: typeof fetch;
  readonly #maxRetries: number;
  readonly #newKey: () => string;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#token = options.token;
    this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.#maxRetries = options.maxRetries ?? 2;
    this.#newKey = options.newIdempotencyKey ?? (() => globalThis.crypto.randomUUID());
  }

  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<Reply<T>> {
    const url = `${this.baseUrl}${path}${options.query ? `?${options.query}` : ""}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json; charset=utf-8";
    if (options.ifMatch !== undefined) headers["If-Match"] = etagFor(options.ifMatch);

    // One key for the whole call, so a retry cannot run the write twice.
    const isWrite = WRITES.has(method);
    const keyed = isWrite && options.idempotent !== false && method !== "DELETE";
    if (keyed) headers["Idempotency-Key"] = this.#newKey();
    const canRetry = !isWrite || keyed || method === "DELETE";

    let attempt = 0;
    for (;;) {
      const token = typeof this.#token === "function" ? await this.#token() : this.#token;
      const sent = token ? { ...headers, Authorization: `Bearer ${token}` } : headers;
      let error: FalakError;
      try {
        const init: RequestInit = { method, headers: sent };
        if (options.body !== undefined) init.body = JSON.stringify(options.body);
        if (options.signal) init.signal = options.signal;
        const response = await this.#fetch(url, init);
        if (response.ok) return await readReply<T>(response);
        error = await readError(response);
      } catch (cause) {
        if (cause instanceof FalakError) {
          error = cause;
        } else if (options.signal?.aborted) {
          throw cause;
        } else {
          error = new FalakError(0, { detail: "Could not reach the server." }, { cause });
        }
      }
      const retryable = error.status === 0 || RETRY_STATUS.has(error.status);
      if (!canRetry || !retryable || attempt >= this.#maxRetries) throw error;
      attempt += 1;
      await sleep(error.retryAfter !== undefined ? error.retryAfter * 1000 : 200 * 2 ** attempt, options.signal);
    }
  }

  async list<Row>(path: string, entity: string, options?: ListOptions<Row>): Promise<Page<Row>> {
    const reply = await this.request<Page<Row>>("GET", path, { query: buildQuery(entity, options) });
    return reply.data;
  }

  /** Every record, one page at a time, following cursors until there are no more. */
  async *iterate<Row>(path: string, entity: string, options: ListOptions<Row> = {}): AsyncGenerator<Row> {
    let after = options.after;
    for (;;) {
      const next: ListOptions<Row> = after === undefined ? options : { ...options, after };
      const page = await this.list<Row>(path, entity, next);
      yield* page.data;
      if (!page.meta.has_more || !page.meta.next_cursor) return;
      after = page.meta.next_cursor;
    }
  }
}

async function readReply<T>(response: Response): Promise<Reply<T>> {
  const etag = response.headers.get("ETag");
  if (response.status === 204) return { data: undefined as T, etag, status: 204 };
  const text = await response.text();
  return { data: (text ? JSON.parse(text) : undefined) as T, etag, status: response.status };
}

async function readError(response: Response): Promise<FalakError> {
  let problem: Problem = {};
  try {
    const parsed: unknown = JSON.parse(await response.text());
    if (parsed !== null && typeof parsed === "object") problem = parsed as Problem;
  } catch {
    // Not JSON (for example an error page from a proxy): keep the status only.
  }
  const header = response.headers.get("Retry-After");
  const seconds = header === null ? NaN : Number(header);
  return new FalakError(response.status, problem, {
    retryAfter: Number.isFinite(seconds) ? seconds : undefined,
  });
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const timer = setTimeout(resolve, Math.min(ms, 10_000));
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}
