// Falak Office console. No framework, no inline script, no innerHTML: every value is put
// on the page with textContent or a control's value, so nothing a person types or an app
// names can inject markup.
"use strict";

const main = document.getElementById("main");
const tabsEl = document.getElementById("tabs");
const who = document.getElementById("who");
const logoutButton = document.getElementById("logout");
const KEY = "falak-office-session";

let session = null; // { access, refresh, email }
let overview = null;

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
    else if (k in e) e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return e;
}

function save() { if (session) sessionStorage.setItem(KEY, JSON.stringify(session)); else sessionStorage.removeItem(KEY); }

async function raw(method, path, body, token) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = "Bearer " + token;
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  return { status: res.status, ok: res.ok, data };
}

function problem(r) {
  const d = r.data || {};
  const e = new Error(d.detail || d.title || `Error ${r.status}`);
  e.status = r.status;
  return e;
}

async function refreshTokens() {
  if (!session || !session.refresh) return false;
  const r = await raw("POST", "/v1/auth/refresh", { refresh_token: session.refresh });
  if (!r.ok || !r.data.access_token) return false;
  session.access = r.data.access_token;
  session.refresh = r.data.refresh_token;
  save();
  return true;
}

async function api(method, path, body) {
  let r = await raw(method, path, body, session && session.access);
  if (r.status === 401 && (await refreshTokens())) r = await raw(method, path, body, session.access);
  if (r.status === 401) { signOut("Your session ended. Sign in again."); throw new Error("Signed out"); }
  if (!r.ok) throw problem(r);
  return r.data;
}

// Two columns on a wide screen: the list or the main thing on the left, what you do about it on the right.
function cols(left, right) { return el("div", { class: "cols" }, el("div", {}, ...left), el("aside", {}, ...right)); }
function side(title, ...body) { return el("div", { class: "card side" }, el("h2", {}, title), ...body); }

function show(...nodes) { main.replaceChildren(...nodes); }
function say(box, text, cls) { box.replaceChildren(el("p", { class: cls || "note" }, text)); }
function when(t) { return t ? new Date(t * 1000).toLocaleString() : ""; }

async function copy(text, button) {
  try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; setTimeout(() => (button.textContent = "Copy"), 1500); }
  catch { button.textContent = "Select and copy"; }
}

function command(text) {
  const b = el("button", { type: "button" }, "Copy");
  b.addEventListener("click", () => copy(text, b));
  return el("div", {}, el("pre", {}, text), b);
}

// ------------------------------------------------------------------ setup

async function boot() {
  const status = await raw("GET", "/v1/_office/status");
  if (status.ok && status.data.setup_needed) return setupView();
  try { session = JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { session = null; }
  if (session) {
    try { await enter(); return; } catch { /* fall through to sign-in */ }
  }
  signInView(status.data && status.data.sign_in_with_provider);
}

function setupView() {
  const params = new URLSearchParams(location.search);
  const token = el("input", { type: "text", name: "token", value: params.get("setup") || "", autocomplete: "off", spellcheck: false });
  const email = el("input", { type: "email", name: "email", autocomplete: "username" });
  const password = el("input", { type: "password", name: "password", autocomplete: "new-password" });
  const again = el("input", { type: "password", name: "again", autocomplete: "new-password" });
  const address = el("input", { type: "text", name: "address", value: location.origin });
  const out = el("div");
  const form = el("form", {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        if (password.value !== again.value) return say(out, "The two passwords are not the same.", "err");
        say(out, "Setting up…");
        const r = await raw("POST", "/v1/_office/setup", {
          token: token.value.trim(), email: email.value, password: password.value, issuer: address.value.trim(),
        });
        if (!r.ok) return say(out, r.status === 403 ? "That setup code is not right, or Office is already set up." : problem(r).message, "err");
        const login = await raw("POST", "/v1/auth/login", { email: email.value, password: password.value });
        password.value = again.value = "";
        if (login.ok) {
          session = { access: login.data.access_token, refresh: login.data.refresh_token, email: email.value };
          save();
          history.replaceState(null, "", "/");
          await enter(r.data.restart_needed ? "restart" : "welcome");
        } else signInView();
      },
    },
  },
    el("div", { class: "fields" },
      el("label", {}, "Setup code", token, el("span", { class: "note" }, "From the terminal where Office started.")),
      el("label", {}, "Your email", email, el("span", { class: "note" }, "You sign in with this.")),
      el("label", {}, "Password", password, el("span", { class: "note" }, "At least 12 characters.")),
      el("label", {}, "Repeat password", again),
      el("label", { class: "wide" }, "Public address of this Office", address,
        el("span", { class: "note" }, "What apps and people type to reach it. Use https on a real server. You can change it later."))),
    el("button", { class: "primary", type: "submit" }, "Create the administrator"),
    out);
  const step = (n, title, text, on) => el("li", { class: on ? "on" : "" }, el("b", {}, n), el("div", {}, el("strong", {}, title), el("span", {}, text)));
  show(el("div", { class: "split" },
    el("div", { class: "intro" },
      el("h1", {}, "Set up Falak Office"),
      el("p", {}, "One sign-in for all your apps. This takes about a minute."),
      el("ol", { class: "steps" },
        step("1", "Make the administrator", "You, with a password. This page.", true),
        step("2", "Connect an app", "One command per app, from the Apps tab.", false),
        step("3", "Add people", "Then give each person the apps they may open.", false))),
    el("div", { class: "card" }, form)));
}

function signInView(withProvider, message) {
  tabsEl.hidden = true;
  const email = el("input", { type: "email", name: "email", autocomplete: "username" });
  const password = el("input", { type: "password", name: "password", autocomplete: "current-password" });
  const out = el("div");
  const form = el("form", {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        const r = await raw("POST", "/v1/auth/login", { email: email.value, password: password.value });
        if (!r.ok) return say(out, "Sign-in failed. Check your details.", "err");
        password.value = "";
        session = { access: r.data.access_token, refresh: r.data.refresh_token, email: email.value };
        save();
        try { await enter(); } catch (e) { session = null; save(); say(out, e.status === 403 ? "This account is not an administrator." : e.message, "err"); }
      },
    },
  }, el("label", {}, "Email", email), el("label", {}, "Password", password),
    el("button", { class: "primary", type: "submit" }, "Sign in"), out);
  show(el("div", { class: "split narrow" },
    el("div", { class: "intro" }, el("h1", {}, "Sign in to Office"),
      el("p", {}, message || "Administrators manage apps, people and access here."),
      withProvider ? el("p", { class: "note" }, "People who sign in through your identity provider use the app's own sign-in button, not this page.") : ""),
    el("div", { class: "card" }, form)));
}

function signOut(message) {
  session = null; save(); overview = null;
  who.textContent = ""; logoutButton.hidden = true; tabsEl.hidden = true;
  signInView(false, message);
}

logoutButton.addEventListener("click", async () => {
  if (session) await raw("POST", "/v1/auth/logout", { refresh_token: session.refresh });
  signOut("Signed out.");
});


// ------------------------------------------------------------------ charts (plain SVG)

let rangeDays = 14;
const NS = "http://www.w3.org/2000/svg";

function svg(tag, attrs, ...kids) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v));
  for (const kid of kids) e.append(kid);
  return e;
}

// A top value that splits into four even steps with whole numbers.
function niceMax(v) {
  if (v <= 4) return 4;
  const unit = v <= 40 ? 4 : 4 * 10 ** Math.floor(Math.log10(v / 4));
  return Math.ceil(v / unit) * unit;
}

function dayLabel(day, short) {
  const d = new Date(day * 86400000);
  return short ? String(d.getUTCDate()).padStart(2, "0") : d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

const W = 640, H = 250, PL = 34, PB = 26, PT = 8, PR = 6;

function frame(max) {
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img" });
  const plotH = H - PB - PT;
  for (let i = 0; i <= 4; i++) {
    const y = PT + plotH - (plotH * i) / 4;
    s.append(svg("line", { class: "grid", x1: PL, x2: W - PR, y1: y, y2: y }));
    const t = svg("text", { class: "axis", x: PL - 8, y: y + 4, "text-anchor": "end" });
    t.textContent = String((max * i) / 4);
    s.append(t);
  }
  return { s, plotH };
}

function barChart(values, firstDay) {
  const max = niceMax(Math.max(...values, 0));
  const { s, plotH } = frame(max);
  s.setAttribute("aria-label", "App tokens per day");
  const grad = svg("linearGradient", { id: "bars", x1: 0, x2: 0, y1: 0, y2: 1 },
    svg("stop", { offset: "0%", "stop-color": "#3a4f62" }), svg("stop", { offset: "100%", "stop-color": "#b9c3cc" }));
  s.prepend(svg("defs", {}, grad));
  const slot = (W - PL - PR) / values.length;
  const bw = Math.min(26, slot * 0.58);
  const every = values.length > 16 ? Math.ceil(values.length / 10) : 1;
  values.forEach((v, i) => {
    const x = PL + slot * i + (slot - bw) / 2;
    const h = v === 0 ? 6 : Math.max(8, (v / max) * plotH);
    const bar = svg("rect", { x, y: PT + plotH - h, width: bw, height: h, rx: Math.min(bw / 2, h / 2), class: v === 0 ? "bar-zero" : "", fill: v === 0 ? "" : "url(#bars)" });
    const tip = svg("title"); tip.textContent = `${dayLabel(firstDay + i)}: ${v}`;
    bar.append(tip); s.append(bar);
    if (i % every === 0) {
      const t = svg("text", { class: "axis", x: x + bw / 2, y: H - 8, "text-anchor": "middle" });
      t.textContent = dayLabel(firstDay + i, true); s.append(t);
    }
  });
  return s;
}

function lineChart(a, b, firstDay) {
  const max = niceMax(Math.max(...a, ...b, 0));
  const { s, plotH } = frame(max);
  s.setAttribute("aria-label", "Sign-ins per day");
  const n = a.length;
  const px = (i) => PL + ((W - PL - PR - 8) * i) / Math.max(1, n - 1) + 4;
  const py = (v) => PT + plotH - (v / max) * plotH;
  const every = Math.ceil(n / 6);
  for (let i = 0; i < n; i += every) {
    const t = svg("text", { class: "axis", x: px(i), y: H - 8, "text-anchor": "middle" });
    t.textContent = dayLabel(firstDay + i); s.append(t);
  }
  for (const [vals, cls] of [[a, "a"], [b, "b"]]) {
    const d = vals.map((v, i) => `${i ? "L" : "M"}${px(i).toFixed(1)} ${py(v).toFixed(1)}`).join(" ");
    s.append(svg("path", { class: "line " + cls, d }));
    if (n <= 16) vals.forEach((v, i) => {
      const dot = svg("circle", { class: "dot " + cls, cx: px(i), cy: py(v), r: 3 });
      const tip = svg("title"); tip.textContent = `${dayLabel(firstDay + i)}: ${v}`;
      dot.append(tip); s.append(dot);
    });
  }
  return s;
}

function delta(cur, prev, goodWhenUp) {
  if (cur === 0 && prev === 0) return el("span", { class: "delta" }, "no change");
  if (prev === 0) return el("span", { class: "delta " + (goodWhenUp ? "up" : "down") }, "↑ new");
  const pct = Math.round(((cur - prev) / prev) * 100);
  const arrow = pct > 0 ? "↑" : pct < 0 ? "↓" : "→";
  const cls = pct === 0 ? "" : (pct > 0) === goodWhenUp ? " up" : " down";
  return el("span", { class: "delta" + cls }, `${arrow} ${Math.abs(pct)}%`);
}

function kpi(label, value, deltaNode) {
  return el("div", { class: "card kpi" }, el("div", { class: "label" }, label), el("div", { class: "value" }, el("b", {}, String(value)), deltaNode));
}

function seen(day, today) {
  if (day === null || day === undefined) return el("span", { class: "muted" }, "never");
  const ago = today - day;
  return ago <= 0 ? "today" : ago === 1 ? "yesterday" : `${ago} days ago`;
}

// ------------------------------------------------------------------ console

const TABS = [
  ["overview", "Overview"], ["apps", "Apps"], ["people", "People"], ["access", "Access"],
  ["signin", "Sign-in"], ["keys", "Keys and revocation"], ["activity", "Activity"],
];

async function enter(first) {
  overview = await api("GET", "/v1/_office/overview"); // fails for anyone who is not an administrator
  who.textContent = session.email;
  logoutButton.hidden = false;
  tabsEl.hidden = false;
  go(first === "welcome" || first === "restart" ? "overview" : "overview", first);
}

function go(tab, first) {
  tabsEl.replaceChildren(...TABS.map(([id, label]) =>
    el("button", { class: id === tab ? "on" : "", on: { click: () => go(id) } }, label)));
  views[tab](first).catch((e) => { if (e.message !== "Signed out") show(el("p", { class: "err" }, e.message)); });
}

async function reload() { overview = await api("GET", "/v1/_office/overview"); }

function banner() {
  return overview.restart_needed
    ? el("div", { class: "banner" }, `The public address was changed to ${overview.saved_issuer}. Restart Office to use it. Until then tokens still carry ${overview.issuer}.`)
    : "";
}

const views = {
  async overview(first) {
    await reload();
    const st = await api("GET", `/v1/_office/stats?days=${rangeDays}`);
    const c = overview.counts;
    const T = st.totals, P = st.previous, S = st.series;
    const signins = T.sign_in + T.sign_in_provider;
    const prevSignins = P.sign_in + P.sign_in_provider;
    const okSeries = S.sign_in.map((n, i) => n + S.sign_in_provider[i]);
    const today = S.app_token.length - 1;
    const busiest = Math.max(...S.app_token);
    const quiet = signins + T.app_token + T.sign_in_failed === 0;

    const range = el("select", { class: "chipselect", "aria-label": "Time range", on: { change: (ev) => { rangeDays = Number(ev.target.value); go("overview"); } } },
      el("option", { value: "7" }, "Last week"), el("option", { value: "14" }, "Last 2 weeks"), el("option", { value: "30" }, "Last 30 days"));
    range.value = String(rangeDays);

    const next = [];
    if (!c.apps) next.push("Connect your first app (Apps).");
    if (c.people < 2) next.push("Add the people who will use your apps (People).");
    if (c.apps && !c.memberships) next.push("Give people access to an app (Access).");
    if (!overview.oidc) next.push("Optional: sign in through Clerk, Auth0 or another provider (Sign-in).");

    show(
      first === "welcome" ? el("div", { class: "banner" }, "Office is set up. You are signed in as its administrator.") : "",
      first === "restart" ? el("div", { class: "banner" }, `Saved the public address ${overview.saved_issuer}. Restart Office to use it.`) : "",
      banner(),
      el("div", { class: "kpis" },
        kpi("Sign-ins", signins, delta(signins, prevSignins, true)),
        kpi("App tokens", T.app_token, delta(T.app_token, P.app_token, true)),
        kpi("Failed sign-ins", T.sign_in_failed, delta(T.sign_in_failed, P.sign_in_failed, false)),
        kpi("People", c.people, el("span", { class: "delta" + (st.new_people_7d ? " up" : "") }, st.new_people_7d ? `↑ ${st.new_people_7d} this week` : "none new"))),
      el("div", { class: "charts" },
        el("div", { class: "card" },
          el("div", { class: "chart-head" }, el("h2", {}, "App tokens"), range),
          el("div", { class: "trio" },
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(T.app_token)), delta(T.app_token, P.app_token, true)), el("span", {}, `In ${rangeDays} days`)),
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(S.app_token[today]))), el("span", {}, "Today")),
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(busiest))), el("span", {}, "Busiest day"))),
          barChart(S.app_token, st.first_day),
          quiet ? el("p", { class: "chart-note" }, "Nothing yet. This fills in as people sign in and apps ask for tokens.") : ""),
        el("div", { class: "card" },
          el("div", { class: "chart-head" }, el("h2", {}, "Sign-ins"),
            el("div", { class: "legend" },
              el("span", {}, el("i", { class: "dot-a" }), "Succeeded"), el("span", {}, el("i", { class: "dot-b" }), "Failed"))),
          el("div", { class: "trio" },
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(signins)), delta(signins, prevSignins, true)), el("span", {}, `In ${rangeDays} days`)),
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(T.sign_in_provider))), el("span", {}, "Through a provider")),
            el("div", {}, el("p", { class: "tv" }, el("b", {}, String(T.sign_in_failed))), el("span", {}, "Failed"))),
          lineChart(okSeries, S.sign_in_failed, st.first_day))),
      el("div", { class: "two" },
        el("div", {}, el("h2", {}, `Apps (${c.apps})`),
          st.apps.length ? table(["App", "Tier", `Tokens, ${rangeDays} days`, "Last heard from", ""], st.apps.map((a) => [
            el("span", { class: "approw" }, el("span", { class: "pill" + (a.status === "active" ? "" : " bad") }), el("span", { class: "name" }, a.name)),
            el("span", { class: "chip" }, `Tier ${a.tier}`), String(a.tokens), seen(a.last_seen_day, st.first_day + rangeDays - 1), ""]))
            : el("div", { class: "empty" }, "No apps yet. Connect one in Apps.")),
        el("div", {}, el("h2", {}, next.length ? "Next" : "All set"),
          el("div", { class: "card" },
            next.length ? el("ul", {}, ...next.map((n) => el("li", {}, n))) : el("p", {}, "Apps, people and access are in place."),
            el("p", { class: "note" }, "Public address"), el("code", {}, overview.issuer),
            el("p", { class: "note" }, "Key set"), el("code", {}, overview.jwks_url),
            el("p", { class: "note" }, `Falak Office ${overview.version}`)))));
  },

  async apps() {
    await reload();
    const apps = (await api("GET", "/v1/_office/apps")).data;
    const name = el("input", { type: "text", name: "app", placeholder: "notebook" });
    const tier = el("select", {}, el("option", { value: "1" }, "Tier 1: keeps working if Office is down"),
      el("option", { value: "2" }, "Tier 2: reads only if Office is down for long"));
    const out = el("div");
    const form = el("form", {
      on: {
        submit: async (ev) => {
          ev.preventDefault();
          try {
            const r = await api("POST", "/v1/_office/enrollments", { app: name.value.trim(), tier: Number(tier.value) });
            const cmd = `FALAK_ENROLL_TOKEN='${r.token}' falak office enroll ./${r.app} --office ${overview.issuer} --name ${r.app}`;
            out.replaceChildren(el("p", { class: "ok" }, `Ready. This code works once and ends ${when(r.expires_at)}. Run, in the app's folder:`), command(cmd));
          } catch (e) { say(out, e.message, "err"); }
        },
      },
    }, el("div", { class: "row stack" }, el("label", {}, "App name", name), el("label", {}, "Trust tier", tier),
      el("button", { class: "primary", type: "submit" }, "Make an enrollment code")), out);
    show(banner(), el("h1", {}, "Apps"),
      el("p", { class: "note" }, "An app joins once with a single-use code. After that people sign in once and reach every app they have access to."),
      cols([apps.length ? table(["App", "Tier", "Status", "Joined", ""], apps.map((a) => [
        a.name, String(a.tier), el("span", { class: "pill" + (a.status === "active" ? "" : " bad") }, a.status), when(a.created_at),
        a.status === "active" ? el("button", { class: "danger", on: { click: async () => {
          if (!confirm(`Cut ${a.name} off from Office? It stops accepting sign-ins within seconds.`)) return;
          await api("POST", `/v1/_office/apps/${encodeURIComponent(a.name)}/revoke`, {}); go("apps");
        } } }, "Cut off") : "",
      ])) : el("div", { class: "empty" }, "No apps yet. Make an enrollment code on the right.")],
        [side("Connect an app", form)]));
  },

  async people() {
    const people = (await api("GET", "/v1/_office/users")).data;
    const email = el("input", { type: "email", name: "email" });
    const password = el("input", { type: "text", name: "password", autocomplete: "off" });
    const admin = el("input", { type: "checkbox" });
    const out = el("div");
    const form = el("form", {
      on: {
        submit: async (ev) => {
          ev.preventDefault();
          try {
            await api("POST", "/v1/_office/users", { email: email.value, password: password.value, roles: admin.checked ? ["office_admin"] : [] });
            go("people");
          } catch (e) { say(out, e.message, "err"); }
        },
      },
    }, el("div", { class: "row stack" }, el("label", {}, "Email", email), el("label", {}, "First password", password),
      el("label", { class: "check" }, admin, "Administrator"), el("button", { class: "primary", type: "submit" }, "Add person")), out);
    show(el("h1", {}, "People"),
      el("p", { class: "note" }, "Accounts are made here. There is no public sign-up. People who use an identity provider are linked to the account with the same verified email."),
      cols([table(["Email", "Role", "Added"], people.map((p) => [p.email, p.roles.includes("office_admin") ? el("span", { class: "pill info" }, "administrator") : "", when(p.created_at)]))],
        [side("Add a person", form)]));
  },

  async access() {
    const [m, people, apps] = await Promise.all([
      api("GET", "/v1/_office/memberships"), api("GET", "/v1/_office/users"), api("GET", "/v1/_office/apps")]);
    const who = el("select", {}, ...people.data.map((p) => el("option", { value: p.email }, p.email)));
    const app = el("select", {}, ...apps.data.map((a) => el("option", { value: a.name }, a.name)));
    const roles = el("input", { type: "text", placeholder: "teacher, editor (optional)" });
    const tenant = el("input", { type: "text", placeholder: "workspace id (optional)" });
    const out = el("div");
    const form = el("form", {
      on: {
        submit: async (ev) => {
          ev.preventDefault();
          try {
            await api("PUT", "/v1/_office/memberships", {
              email: who.value, app: app.value, tenant: tenant.value.trim(),
              roles: roles.value.split(",").map((x) => x.trim()).filter(Boolean),
            });
            go("access");
          } catch (e) { say(out, e.message, "err"); }
        },
      },
    }, el("div", { class: "row stack" }, el("label", {}, "Person", who), el("label", {}, "App", app),
      el("label", {}, "Roles in that app", roles), el("label", {}, "Workspace", tenant),
      el("button", { class: "primary", type: "submit" }, "Give access")), out);
    show(el("h1", {}, "Access"),
      el("p", { class: "note" }, "Who may open which app, with which roles. The app's own rules decide what the roles allow."),
      !(apps.data.length && people.data.length) ? el("div", { class: "empty" }, "Connect an app and add a person first, then give them access here.") : "",
      !(apps.data.length && people.data.length) ? "" : cols([m.data.length ? table(["Person", "App", "Roles", "Workspace", ""], m.data.map((x) => [
        x.email, x.app, x.roles.join(", "), x.tenant,
        el("button", { class: "danger", on: { click: async () => { await api("DELETE", "/v1/_office/memberships", { user_id: x.user_id, app: x.app }); go("access"); } } }, "Remove"),
      ])) : el("div", { class: "empty" }, "Nobody has access to any app yet.")],
        [side("Give access", form)]));
  },

  async signin() {
    await reload();
    const o = overview.oidc;
    const issuer = el("input", { type: "text", value: o ? o.issuer : "", placeholder: "https://your-app.clerk.accounts.dev" });
    const audience = el("input", { type: "text", value: o ? o.audience : "", placeholder: "client id" });
    const domains = el("input", { type: "text", value: o ? o.auto_create_domains.join(", ") : "", placeholder: "example.com (optional)" });
    const out = el("div");
    const form = el("form", {
      on: {
        submit: async (ev) => {
          ev.preventDefault();
          say(out, "Saving and checking the provider…");
          try {
            const r = await api("PUT", "/v1/_office/settings/oidc", {
              issuer: issuer.value, audience: audience.value,
              auto_create_domains: domains.value.split(",").map((x) => x.trim()).filter(Boolean),
            });
            say(out, r.reachable ? "Saved. The provider answered." : `Saved, but the provider did not answer: ${r.problem}`, r.reachable ? "ok" : "warn");
          } catch (e) { say(out, e.message, "err"); }
        },
      },
    }, el("label", {}, "Provider address (issuer)", issuer), el("label", {}, "Audience (client id)", audience),
      el("label", {}, "Make accounts automatically for these email domains", domains),
      el("div", { class: "row" }, el("button", { class: "primary", type: "submit" }, o ? "Save changes" : "Turn on"),
        o ? el("button", { type: "button", class: "danger", on: { click: async () => { await api("PUT", "/v1/_office/settings/oidc", { enabled: false }); go("signin"); } } }, "Turn off") : ""),
      out);
    const addr = el("input", { type: "text", value: overview.saved_issuer || overview.issuer });
    const addrOut = el("div");
    const addrForm = el("form", {
      on: { submit: async (ev) => {
        ev.preventDefault();
        try {
          const r = await api("PUT", "/v1/_office/settings/address", { issuer: addr.value.trim() });
          say(addrOut, r.restart_needed ? "Saved. Restart Office to use it." : "Saved.", r.restart_needed ? "warn" : "ok");
        } catch (e) { say(addrOut, e.message, "err"); }
      } },
    }, el("div", { class: "row" }, el("label", {}, "Public address", addr), el("button", { type: "submit" }, "Save address")), addrOut);
    show(banner(), el("h1", {}, "Sign-in"),
      el("p", {}, "People sign in with a password you gave them, or through an identity provider such as Clerk, Auth0, Keycloak or Google. The provider does passkeys and multi-factor; Office only checks its signed ID token."),
      el("div", { class: "two" },
        el("div", { class: "card" }, el("h2", {}, "Identity provider"), el("p", { class: "note" }, o ? "On" : "Off"), form,
          el("p", { class: "note" }, "Your app's sign-in page gets an ID token from the provider and sends it to Office at ", el("code", {}, "POST /v1/auth/oidc/exchange"), ".")),
        el("div", { class: "card" }, el("h2", {}, "Public address"), addrForm)));
  },

  async keys() {
    await reload();
    const out = el("div");
    const kind = el("select", {}, el("option", { value: "subject" }, "A person (all their tokens)"),
      el("option", { value: "token" }, "One token"), el("option", { value: "app" }, "An app"));
    const id = el("input", { type: "text", placeholder: "person id, token id or app name" });
    const rev = el("form", {
      on: { submit: async (ev) => {
        ev.preventDefault();
        try { const r = await api("POST", "/v1/_office/revocations", { kind: kind.value, id: id.value.trim() }); say(out, `Revoked. Feed version ${r.version}. Apps pick it up within seconds.`, "ok"); }
        catch (e) { say(out, e.message, "err"); }
      } },
    }, el("div", { class: "row" }, el("label", {}, "Revoke", kind), el("label", {}, "Which", id), el("button", { class: "danger", type: "submit" }, "Revoke")), out);
    const keyOut = el("div");
    show(el("h1", {}, "Keys and revocation"),
      el("div", { class: "two" },
      el("div", { class: "card" }, el("h2", {}, `Signing keys (${overview.signing_keys})`),
        el("p", { class: "note" }, "Rotating adds a new key and keeps the old one, so nothing fails while apps learn the new key. Retire the old keys once every token signed with them has expired (a few minutes for tier 2, fifteen for tier 1)."),
        el("div", { class: "row" },
          el("button", { on: { click: async () => { const r = await api("POST", "/v1/_office/keys/rotate", {}); say(keyOut, `Rotated. New key ${r.kid}. ${r.keys} keys are published.`, "ok"); await reload(); } } }, "Rotate the signing key"),
          el("button", { on: { click: async () => { if (!confirm("Retire the old keys? Tokens signed with them stop working.")) return; const r = await api("POST", "/v1/_office/keys/retire", {}); say(keyOut, `Retired. ${r.keys} key is published.`, "ok"); await reload(); } } }, "Retire old keys")),
        keyOut, el("p", { class: "note" }, "Key set: ", el("a", { href: "/.well-known/jwks.json" }, overview.jwks_url))),
      el("div", { class: "card" }, el("h2", {}, "Revoke"), rev,
        el("p", { class: "note" }, `Feed version ${overview.feed_version}.`))));
  },

  async activity() {
    const log = (await api("GET", "/v1/_office/audit")).data;
    show(el("h1", {}, "Activity"), el("p", { class: "note" }, "Administrative actions, newest first. Each entry commits to the one before it."),
      log.length ? table(["#", "When", "Who", "What", "Detail"], log.map((l) => [String(l.seq), when(l.at), l.actor.slice(0, 12), l.action, l.detail])) : el("div", { class: "empty" }, "Nothing yet."));
  },
};


function table(head, rows) {
  return el("table", {}, el("thead", {}, el("tr", {}, ...head.map((h) => el("th", {}, h)))),
    el("tbody", {}, ...rows.map((r) => el("tr", {}, ...r.map((c) => el("td", {}, c))))));
}

boot().catch((e) => show(el("p", { class: "err" }, "Office did not answer. " + e.message)));
