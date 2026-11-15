/** One field-level problem inside a `FalakError`. */
export interface InvalidParam {
  name: string;
  reason: string;
  code: string;
}

/** The RFC 9457 body the API returns for every error. */
export interface Problem {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  code?: string;
  instance?: string;
  request_id?: string;
  invalid_params?: InvalidParam[];
}

/**
 * An error returned by the API, or a failure to reach it.
 *
 * Match on `code` (stable) rather than `message` (for people). `status` is 0 when no
 * response arrived.
 */
export class FalakError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string;
  readonly instance: string | undefined;
  readonly requestId: string | undefined;
  readonly invalidParams: readonly InvalidParam[];
  /** Seconds the server asked the caller to wait, if it said. */
  readonly retryAfter: number | undefined;

  constructor(
    status: number,
    problem: Problem,
    options: { retryAfter?: number | undefined; cause?: unknown } = {},
  ) {
    const detail = problem.detail ?? problem.title ?? `Request failed with status ${status}`;
    super(detail, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "FalakError";
    this.status = status;
    this.code = problem.code ?? (status === 0 ? "network_error" : "unknown_error");
    this.detail = detail;
    this.instance = problem.instance;
    this.requestId = problem.request_id;
    this.invalidParams = problem.invalid_params ?? [];
    this.retryAfter = options.retryAfter;
  }

  /** True when sending the same request again can succeed. */
  get retryable(): boolean {
    return (
      this.status === 0 ||
      this.status === 429 ||
      this.status === 503 ||
      this.status === 504
    );
  }

  /** True for a stale `If-Match`: reload the record and try again. */
  get isVersionConflict(): boolean {
    return this.status === 412;
  }

  /** Problems keyed by field name, for showing messages next to inputs. */
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const p of this.invalidParams) out[p.name] ??= p.reason;
    return out;
  }
}
