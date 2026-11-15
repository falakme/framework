// Falak Studio. No framework, no inline script, no innerHTML: every value is put on the
// page with textContent or a form control's value, so a record cannot inject markup.
"use strict";

const main = document.getElementById("main");
const who = document.getElementById("who");
const logoutButton = document.getElementById("logout");
let csrf = "";
let state = { apps: [], app: null, schema: null, entity: null };

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k in e) e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const kid of kids) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET") headers["x-studio-csrf"] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* an empty body */ }
  if (!res.ok) {
    const e = new Error((data && (data.detail || data.title)) || `Error ${res.status}`);
    e.status = res.status;
    throw e;
  }
  return data;
}

function show(...nodes) { main.replaceChildren(...nodes); }
function errorLine(e) { return el("p", { class: "err", role: "alert" }, e.message || String(e)); }

function loginView(message) {
  const email = el("input", { type: "text", name: "email", autocomplete: "username" });
  const password = el("input", { type: "password", name: "password", autocomplete: "current-password" });
  const out = el("div");
  const form = el("form", {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        try {
          const me = await api("POST", "/api/login", { email: email.value, password: password.value });
          password.value = "";
          start(me);
        } catch (e) { out.replaceChildren(errorLine(e)); }
      },
    },
  },
    el("label", {}, "Email", email),
    el("label", {}, "Password", password),
    el("button", { type: "submit" }, "Sign in"),
    out);
  show(el("div", { class: "center" }, el("h1", {}, "Sign in to Studio"), message ? el("p", { class: "note" }, message) : "", el("div", { class: "card" }, form)));
}

function start(me) {
  csrf = me.csrf;
  state.apps = me.apps;
  who.textContent = me.email;
  logoutButton.hidden = false;
  if (!state.apps.length) { show(el("p", {}, "No apps are set up for Studio.")); return; }
  openApp(state.apps[0]);
}

async function openApp(name) {
  state.app = name; state.entity = null;
  try {
    state.schema = await api("GET", `/api/apps/${encodeURIComponent(name)}/schema`);
  } catch (e) { state.schema = null; renderShell(errorLine(e)); return; }
  const first = state.schema.entities[0];
  if (first) openEntity(first.path); else renderShell(el("p", {}, "You can manage nothing in this app."));
}

function renderShell(...content) {
  const apps = el("nav", {}, ...state.apps.map((a) =>
    el("button", { class: a === state.app ? "on" : "", on: { click: () => openApp(a) } }, a)));
  const ents = state.schema ? el("nav", {}, ...state.schema.entities.map((e) =>
    el("button", { class: e.path === state.entity ? "on" : "", on: { click: () => openEntity(e.path) } },
      e.admin.label || e.name))) : "";
  show(apps, ents, ...content);
}

function entityMeta() { return state.schema.entities.find((e) => e.path === state.entity); }

function columnsFor(meta) {
  const named = meta.admin.list_columns.filter((c) => meta.fields.some((f) => f.name === c));
  if (named.length) return named;
  return meta.fields.filter((f) => !f.builtin && !f.encrypted).slice(0, 4).map((f) => f.name);
}

async function openEntity(path, after, filter) {
  state.entity = path;
  const meta = entityMeta();
  const q = new URLSearchParams({ "page[size]": "25" });
  if (after) q.set("page[after]", after);
  if (filter && filter.field && filter.value) q.set(`filter[${filter.field}]`, filter.value);
  let page;
  try {
    page = await api("GET", `/api/apps/${encodeURIComponent(state.app)}/${encodeURIComponent(path)}?${q}`);
  } catch (e) { renderShell(errorLine(e)); return; }
  const cols = columnsFor(meta);
  const search = el("input", { type: "text", placeholder: "exact match", "aria-label": "search" });
  const searchField = meta.admin.search_fields[0];
  const bar = el("div", { class: "bar" },
    searchField ? el("span", {}, `Find by ${searchField}:`) : "",
    searchField ? search : "",
    searchField ? el("button", { on: { click: () => openEntity(path, null, { field: searchField, value: search.value }) } }, "Find") : "",
    meta.can.create ? el("button", { on: { click: () => editView(meta, null) } }, "New") : "");
  const table = el("table", {},
    el("thead", {}, el("tr", {}, ...cols.map((c) => el("th", {}, c)))),
    el("tbody", {}, ...page.data.map((row) =>
      el("tr", { class: "row", on: { click: () => editView(meta, row) } },
        ...cols.map((c) => cell(meta, row, c))))));
  const more = page.meta && page.meta.has_more
    ? el("button", { on: { click: () => openEntity(path, page.meta.next_cursor, filter) } }, "Next page") : "";
  renderShell(bar, page.data.length ? table : el("div", { class: "empty" }, "No rows."), more);
}

function cell(meta, row, name) {
  const f = meta.fields.find((x) => x.name === name);
  const v = row[name];
  const td = el("td", { class: f && (f.pii || f.encrypted) ? "masked" : "" });
  td.textContent = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return td;
}

function editable(f, meta) {
  return !f.builtin && !f.encrypted && f.name !== meta.owner && f.type !== "json" && f.type !== "bytes";
}

function editView(meta, row) {
  const creating = row === null;
  const inputs = new Map();
  const dirty = new Set();
  const out = el("div");
  const rows = [];
  for (const f of meta.fields.filter((x) => editable(x, meta))) {
    let input;
    if (f.type === "bool") {
      input = el("input", { type: "checkbox", checked: !!(row && row[f.name]) });
    } else if (f.type === "int64" || f.type === "decimal_minor") {
      input = el("input", { type: "number", value: row && row[f.name] !== null && row[f.name] !== undefined ? String(row[f.name]) : "" });
    } else {
      input = el("input", { type: "text", value: row && row[f.name] !== null && row[f.name] !== undefined ? String(row[f.name]) : "" });
    }
    input.addEventListener("input", () => dirty.add(f.name));
    input.addEventListener("change", () => dirty.add(f.name));
    inputs.set(f.name, { input, f });
    const extra = [];
    if (f.pii && !creating) {
      extra.push(el("button", {
        type: "button",
        on: {
          click: async () => {
            try {
              const r = await api("POST", `/api/apps/${encodeURIComponent(state.app)}/${encodeURIComponent(meta.path)}/${encodeURIComponent(row.id)}/reveal`, {});
              if (r.data && f.name in r.data) { input.value = r.data[f.name] === null ? "" : String(r.data[f.name]); }
              out.replaceChildren(el("p", { class: "note" }, "Shown once and recorded in the audit log."));
            } catch (e) { out.replaceChildren(errorLine(e)); }
          },
        },
      }, "Reveal"));
    }
    rows.push(el("label", {}, f.pii ? `${f.name} (personal data, masked)` : f.name, input, ...extra));
  }
  const body = () => {
    const values = {};
    for (const name of creating ? inputs.keys() : dirty) {
      const { input, f } = inputs.get(name);
      let v = input.type === "checkbox" ? input.checked : input.value;
      if (f.type === "int64" || f.type === "decimal_minor") v = v === "" ? null : Number(v);
      else if (v === "" && f.nullable) v = null;
      if (creating && v === "" ) continue;
      values[name] = v;
    }
    return values;
  };
  const buttons = [
    el("button", {
      type: "submit",
    }, creating ? "Create" : "Save"),
    el("button", { type: "button", on: { click: () => openEntity(meta.path) } }, "Back"),
  ];
  if (!creating && meta.can.delete) {
    buttons.push(el("button", {
      type: "button",
      on: {
        click: async () => {
          if (!confirm("Delete this record?")) return;
          try {
            await api("DELETE", `/api/apps/${encodeURIComponent(state.app)}/${encodeURIComponent(meta.path)}/${encodeURIComponent(row.id)}`);
            openEntity(meta.path);
          } catch (e) { out.replaceChildren(errorLine(e)); }
        },
      },
    }, "Delete"));
  }
  const form = el("form", {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        try {
          const base = `/api/apps/${encodeURIComponent(state.app)}/${encodeURIComponent(meta.path)}`;
          if (creating) await api("POST", base, { values: body() });
          else if (!meta.can.update) throw new Error("You may not change this record.");
          else await api("PATCH", `${base}/${encodeURIComponent(row.id)}`, { changes: body(), version: row.version });
          openEntity(meta.path);
        } catch (e) { out.replaceChildren(errorLine(e)); }
      },
    },
  }, ...rows, el("div", { class: "bar" }, ...buttons), out);
  renderShell(el("h1", {}, `${creating ? "New" : "Edit"} ${meta.admin.label || meta.name}`), el("div", { class: "card" }, form));
}

logoutButton.addEventListener("click", async () => {
  try { await api("POST", "/api/logout", {}); } catch { /* already out */ }
  csrf = ""; who.textContent = ""; logoutButton.hidden = true;
  loginView("Signed out.");
});

(async () => {
  try { start(await api("GET", "/api/me")); } catch { loginView(); }
})();
