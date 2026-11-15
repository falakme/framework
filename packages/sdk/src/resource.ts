import type { FalakClient, Page } from "./client.ts";
import type { ListOptions } from "./query.ts";

/** Options for a write that may carry a precondition. */
export interface WriteOptions {
  /** The record's `version` (or an ETag). A stale value fails with a 412. */
  ifMatch?: number | string;
  /** Turn automatic idempotency keys off for this call. */
  idempotent?: boolean;
}

/**
 * Typed access to one entity's routes. Generated clients create one per entity.
 *
 * `Row` is the record, `Create` the create body, `Update` the patch body.
 */
export class Resource<Row, Create, Update> {
  protected readonly client: FalakClient;
  /** The entity name, used in `fields[<entity>]`. */
  readonly entity: string;
  /** The route segment, for example `notes`. */
  readonly table: string;

  constructor(client: FalakClient, entity: string, table: string) {
    this.client = client;
    this.entity = entity;
    this.table = table;
  }

  protected get path(): string {
    return `/v1/${this.table}`;
  }

  list(options?: ListOptions<Row>): Promise<Page<Row>> {
    return this.client.list<Row>(this.path, this.entity, options);
  }

  /** Every record that matches, across pages. */
  all(options?: ListOptions<Row>): AsyncGenerator<Row> {
    return this.client.iterate<Row>(this.path, this.entity, options);
  }

  async get(id: string): Promise<Row> {
    return (await this.client.request<Row>("GET", `${this.path}/${encodeURIComponent(id)}`)).data;
  }

  async create(body: Create, options: Pick<WriteOptions, "idempotent"> = {}): Promise<Row> {
    return (
      await this.client.request<Row>("POST", this.path, {
        body,
        ...(options.idempotent === undefined ? {} : { idempotent: options.idempotent }),
      })
    ).data;
  }

  async update(id: string, patch: Update, options: WriteOptions = {}): Promise<Row> {
    return (
      await this.client.request<Row>("PATCH", `${this.path}/${encodeURIComponent(id)}`, {
        body: patch,
        ...(options.ifMatch === undefined ? {} : { ifMatch: options.ifMatch }),
        ...(options.idempotent === undefined ? {} : { idempotent: options.idempotent }),
      })
    ).data;
  }

  async delete(id: string, options: Pick<WriteOptions, "ifMatch"> = {}): Promise<void> {
    await this.client.request<void>("DELETE", `${this.path}/${encodeURIComponent(id)}`, {
      ...(options.ifMatch === undefined ? {} : { ifMatch: options.ifMatch }),
    });
  }

  /** Run a command on a record: `POST /v1/<table>/<id>/<command>`. */
  protected async run<Out = Row>(
    id: string,
    command: string,
    body: Record<string, unknown> = {},
    options: WriteOptions = {},
  ): Promise<Out> {
    return (
      await this.client.request<Out>("POST", `${this.path}/${encodeURIComponent(id)}/${command}`, {
        body,
        ...(options.ifMatch === undefined ? {} : { ifMatch: options.ifMatch }),
        ...(options.idempotent === undefined ? {} : { idempotent: options.idempotent }),
      })
    ).data;
  }
}
