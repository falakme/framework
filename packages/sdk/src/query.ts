/** Filter operators the API accepts (API specification §3.1). */
export type FilterOperator =
  | "eq"
  | "neq"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "in"
  | "like"
  | "is_null";

export type FilterValue = string | number | boolean | null;

/** `{ archived: false }` or `{ created_at: { gte: "2026-11-01T00:00:00Z" } }`. */
export type Filter<Row> = {
  [K in keyof Row]?: FilterValue | { [O in FilterOperator]?: FilterValue | FilterValue[] };
};

export interface ListOptions<Row> {
  /** Records per page (1 to 100). */
  pageSize?: number;
  /** Continue after this cursor (`meta.next_cursor` of the previous page). */
  after?: string;
  /** Go back before this cursor. */
  before?: string;
  filter?: Filter<Row>;
  /** Field names; a leading `-` sorts descending. */
  sort?: ReadonlyArray<string>;
  /** Only these fields. */
  fields?: ReadonlyArray<string>;
  /** Relations to load with each record. */
  include?: ReadonlyArray<string>;
}

function scalar(v: FilterValue): string {
  return v === null ? "null" : String(v);
}

/** Turn list options into the query string the API expects (no leading `?`). */
export function buildQuery<Row>(entity: string, options: ListOptions<Row> = {}): string {
  const params = new URLSearchParams();
  if (options.pageSize !== undefined) params.set("page[size]", String(options.pageSize));
  if (options.after !== undefined) params.set("page[after]", options.after);
  if (options.before !== undefined) params.set("page[before]", options.before);
  if (options.sort?.length) params.set("sort", options.sort.join(","));
  if (options.fields?.length) params.set(`fields[${entity}]`, options.fields.join(","));
  if (options.include?.length) params.set("include", options.include.join(","));
  if (options.filter) {
    for (const [field, spec] of Object.entries(options.filter)) {
      if (spec === undefined) continue;
      if (spec !== null && typeof spec === "object") {
        for (const [op, value] of Object.entries(spec as Record<string, unknown>)) {
          if (value === undefined) continue;
          const text = Array.isArray(value)
            ? value.map((v) => scalar(v as FilterValue)).join(",")
            : scalar(value as FilterValue);
          params.set(`filter[${field}][${op}]`, text);
        }
      } else {
        params.set(`filter[${field}]`, scalar(spec as FilterValue));
      }
    }
  }
  return params.toString();
}
