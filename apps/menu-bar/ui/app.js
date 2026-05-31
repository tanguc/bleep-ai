// Bleep desktop app — hash-routed SPA. No bundler, no framework.
//
// Wire-event types come from crates/bleep-events/bindings/, generated
// from Rust by ts-rs. The `@bleep-events/*` alias is set in jsconfig.json.
// To regenerate after editing Rust types:  cargo test --package bleep-events

/** @typedef {import("@bleep-events/ProxyEvent").ProxyEvent} ProxyEvent */
/** @typedef {import("@bleep-events/RedactedEntry").RedactedEntry} RedactedEntry */
/** @typedef {import("@bleep-events/Summary").Summary} Summary */
/** @typedef {import("@bleep-events/CategoryCount").CategoryCount} CategoryCount */
/** @typedef {import("@bleep-events/RuleCount").RuleCount} RuleCount */
/** @typedef {import("@bleep-events/RedactedRow").RedactedRow} RedactedRow */
/** @typedef {import("@bleep-events/RedactedPage").RedactedPage} RedactedPage */

// Tauri commands exposed by the Rust side. Keep this in sync with
// apps/menu-bar/src-tauri/src/main.rs (`tauri::generate_handler![...]`).
/**
 * @typedef {object} TauriCommands
 * @property {() => Promise<number | null>} get_stats_port
 */

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const POLL_MS = 1000;
const MAX_TAIL = 1000;

// per-item redacted entries, used by lazy-render on first expand. WeakMap so
// detached tail-items get GC'd without us bookkeeping.
const tailEntries = new WeakMap();

const ROUTES = ["dashboard", "rules", "perf", "settings", "drilldown"];
const DEFAULT_ROUTE = "dashboard";

// drilldown state — survives route transitions so scroll resumes cleanly
const drilldown = {
  filter: {},        // { category?, subcategory?, rule_id?, q?, since?, until? }
  rows: [],          // accumulated RedactedRow[]
  cursor: null,      // next page cursor; null = exhausted
  loading: false,
  loadedFirstPage: false,
  // per-column UI filters (client-side, post-fetch). Persist across navigations.
  colFilters: { time: "", category: "", rule: "", subcategory: "", original: "", fake: "" },
  // grouped view state
  viewMode: "grouped",       // "grouped" | "flat"
  groups: new Map(),         // original -> GroupEntry
  expandedGroups: new Set(), // original strings currently expanded
};

let activeRoute = null;
let pollTimer = null;
let statsPort = null;
let tailRowsEmitted = 0;

// live-tail filter state — applied client-side over already-rendered rows.
// Older rows that scrolled past MAX_TAIL are not searchable here; that needs
// a /stats/search endpoint (not built yet).
const tailFilter = {
  /** lowercase free-text query; empty = match all */
  q: "",
  /** "all" | "pii" | "secret" | "infra" */
  cat: "all",
};

// ── perf instrumentation ───────────────────────────────────────────────
// Lightweight timing/metrics. Every measurement is logged to console.debug
// and aggregated in `perf.stats` (count, total ms, min, max, last). Inspect
// at runtime via `window.__bleepPerf.report()` in devtools.
const perf = (() => {
  const stats = new Map(); // name -> { count, totalMs, minMs, maxMs, lastMs, lastAt }
  const recent = []; // ring of last N samples { name, ms, at, meta }
  const RECENT_MAX = 200;
  const SLOW_MS = 50; // threshold for console.warn vs console.debug

  function record(name, ms, meta) {
    let s = stats.get(name);
    if (!s) {
      s = { count: 0, totalMs: 0, minMs: Infinity, maxMs: 0, lastMs: 0, lastAt: 0 };
      stats.set(name, s);
    }
    s.count += 1;
    s.totalMs += ms;
    if (ms < s.minMs) s.minMs = ms;
    if (ms > s.maxMs) s.maxMs = ms;
    s.lastMs = ms;
    s.lastAt = Date.now();
    recent.push({ name, ms, at: s.lastAt, meta });
    if (recent.length > RECENT_MAX) recent.shift();
    const tag = `[perf] ${name} ${ms.toFixed(1)}ms`;
    const detail = meta !== undefined ? meta : "";
    if (ms >= SLOW_MS) console.warn(tag, detail);
    else console.debug(tag, detail);
  }

  function start(name) {
    const t0 = performance.now();
    return (meta) => record(name, performance.now() - t0, meta);
  }

  function time(name, fn, meta) {
    const t0 = performance.now();
    try {
      return fn();
    } finally {
      record(name, performance.now() - t0, meta);
    }
  }

  async function timeAsync(name, fn, meta) {
    const t0 = performance.now();
    try {
      return await fn();
    } finally {
      record(name, performance.now() - t0, meta);
    }
  }

  function report() {
    const rows = [];
    for (const [name, s] of stats) {
      rows.push({
        name,
        count: s.count,
        avg_ms: +(s.totalMs / s.count).toFixed(2),
        min_ms: +s.minMs.toFixed(2),
        max_ms: +s.maxMs.toFixed(2),
        last_ms: +s.lastMs.toFixed(2),
        total_ms: +s.totalMs.toFixed(1),
      });
    }
    rows.sort((a, b) => b.total_ms - a.total_ms);
    console.table(rows);
    return rows;
  }

  function reset() {
    stats.clear();
    recent.length = 0;
  }

  return { record, start, time, timeAsync, report, reset, stats, recent };
})();
window.__bleepPerf = perf;

// ── helpers ────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(d = new Date()) {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** @returns {Promise<number | null>} */
async function getStatsPort() {
  if (statsPort) return statsPort;
  try {
    statsPort = /** @type {number | null} */ (await invoke("get_stats_port"));
    return statsPort;
  } catch (_) { return null; }
}

/**
 * Generic typed GET against the gateway's /stats axum server. Caller pins T
 * to one of the bleep-events response shapes, so downstream property access
 * is checked by the JS language server.
 * @template T
 * @param {number} port
 * @param {string} path
 * @returns {Promise<T>}
 */
async function fetchJson(port, path) {
  const tNet = performance.now();
  const r = await fetch(`http://127.0.0.1:${port}${path}`);
  const netMs = performance.now() - tNet;
  if (!r.ok) {
    perf.record("fetch.error", netMs, { path, status: r.status });
    throw new Error(`${path} ${r.status}`);
  }
  const tParse = performance.now();
  const body = await r.json();
  const parseMs = performance.now() - tParse;
  const size = Array.isArray(body) ? body.length : (body && typeof body === "object" ? Object.keys(body).length : 0);
  perf.record("fetch.net", netMs, { path, status: r.status });
  perf.record("fetch.parse", parseMs, { path, items: size });
  return /** @type {Promise<T>} */ (body);
}

function setConnection(connected) {
  const el = document.getElementById("connection");
  if (!el) return;
  el.textContent = connected ? "● connected" : "○ disconnected";
  el.classList.toggle("connected", connected);
  el.classList.toggle("disconnected", !connected);
}

function severityClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical" || s === "high") return "sev-high";
  if (s === "medium" || s === "moderate") return "sev-med";
  if (s === "low") return "sev-low";
  return "sev-other";
}

const TRUNCATE_AT = 24;

function truncate(s, maxLen = TRUNCATE_AT) {
  const str = String(s ?? "");
  if (str.length <= maxLen) return { display: str, truncated: false };
  return { display: str.slice(0, maxLen) + "…", truncated: true };
}

// Renders a copy-on-click cell. Full value goes into title (native tooltip)
// and data-full (read by the click handler in onRedactionEvent).
function renderCopyCell(value, extraClass = "") {
  const { display, truncated } = truncate(value);
  return `<td class="${extraClass}${truncated ? " truncated" : ""}">
    <code class="copyable" data-full="${escapeHtml(value || "")}" title="${escapeHtml(value || "")}${truncated ? " — click to copy" : ""}">${escapeHtml(display)}</code>
  </td>`;
}

/** @param {RedactedEntry[]} entries */
function renderRedactedDetails(entries) {
  const rows = entries.map((r) => `
    <tr>
      <td class="td-rule">${escapeHtml(r.rule_id || "")}</td>
      <td><span class="pill ${categoryClass(r.category)}">${escapeHtml(r.category || "")}</span></td>
      <td>${escapeHtml(r.subcategory || "")}</td>
      <td><span class="pill ${severityClass(r.severity)}">${escapeHtml(r.severity || "")}</span></td>
      ${renderCopyCell(r.fake_value, "td-fake")}
      ${renderCopyCell(r.original, "td-original")}
    </tr>
  `).join("");
  return `
    <div class="redacted-table-wrap" data-count="${entries.length}">
      <table class="redacted-table">
        <thead>
          <tr><th>Rule</th><th>Category</th><th>Subcategory</th><th>Severity</th><th>Fake value</th><th>Originale</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function categoryClass(category) {
  if (category === "secret") return "cat-secret";
  if (category === "pii") return "cat-pii";
  if (category === "infra") return "cat-infra";
  return "cat-other";
}

function renderBars(container, items, labelKey, secondaryKey, classKey) {
  const tRender = performance.now();
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="empty">no redactions yet</div>';
    perf.record("renderBars", performance.now() - tRender, { id: container.id, items: 0 });
    return;
  }
  const max = Math.max(...items.map((i) => i.count));
  const html = items.map((i) => {
    const pct = max > 0 ? Math.round((i.count / max) * 100) : 0;
    const klass = classKey ? classKey(i) : "cat-other";
    const label = secondaryKey
      ? `<span class="bar-label">${escapeHtml(i[labelKey])} <span class="dim">/ ${escapeHtml(i[secondaryKey])}</span></span>`
      : `<span class="bar-label">${escapeHtml(i[labelKey])}</span>`;
    // encode filter on the element so the click handler can read it without
    // a closure-per-bar (which would balloon if we ever virtualize this list)
    const dataFilter = JSON.stringify(barClickFilter(i, labelKey, secondaryKey));
    return `<div class="bar bar-clickable ${klass}" style="--bar-pct: ${pct}%" data-filter='${escapeHtml(dataFilter)}'>${label}<span class="bar-count">${i.count}</span></div>`;
  }).join("");
  container.innerHTML = html;
  if (!container.dataset.clickBound) {
    container.dataset.clickBound = "1";
    container.addEventListener("click", (e) => {
      const bar = e.target.closest(".bar-clickable");
      if (!bar) return;
      const tClick = performance.now();
      const raw = bar.dataset.filter;
      try {
        const filter = JSON.parse(raw || "{}");
        perf.record("bar.click", performance.now() - tClick, filter);
        openDrilldown(filter);
      } catch (err) {
        // surface the failure instead of swallowing it — without this the
        // click silently does nothing and the user can't tell why.
        console.error("[bar-click] failed to open drilldown", { raw, err });
        perf.record("bar.click.error", performance.now() - tClick, { raw, err: String(err) });
      }
    });
  }
  perf.record("renderBars", performance.now() - tRender, { id: container.id, items: items.length });
}

// derive a /redactions filter shape from one bar row. categories chart uses
// {subcategory, category}; rules chart uses {rule_id}. classKey is implicit
// via labelKey.
function barClickFilter(item, labelKey, secondaryKey) {
  if (labelKey === "subcategory" && secondaryKey === "category") {
    return { category: item.category, subcategory: item.subcategory };
  }
  if (labelKey === "rule_id") {
    return { rule_id: item.rule_id };
  }
  return {};
}

function renderCounter(el, value) {
  if (!el || el.textContent === String(value)) return;
  el.textContent = value;
  el.animate(
    [{ transform: "scale(1.08)" }, { transform: "scale(1)" }],
    { duration: 220, easing: "ease-out" }
  );
}

// ── routing ────────────────────────────────────────────────────────────

function currentRoute() {
  const r = (location.hash || "").replace(/^#/, "");
  return ROUTES.includes(r) ? r : DEFAULT_ROUTE;
}

function navigateTo(route) {
  if (!ROUTES.includes(route)) route = DEFAULT_ROUTE;
  if (location.hash !== `#${route}`) location.hash = `#${route}`;
  else renderRoute(route);
}

function highlightSidebar(route) {
  document.querySelectorAll(".sidebar a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
}

function renderRoute(route) {
  const tRoute = performance.now();
  // drilldown is parameter-bearing — always re-render so filter changes apply
  if (activeRoute === route && route !== "drilldown") {
    perf.record("renderRoute.skip", performance.now() - tRoute, { route });
    return;
  }
  activeRoute = route;
  highlightSidebar(route);

  const tpl = document.getElementById(`route-${route}`);
  const content = document.getElementById("content");
  content.innerHTML = "";
  if (tpl) content.appendChild(tpl.content.cloneNode(true));

  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (route === "dashboard") {
    bindTailFilterControls();
    refreshDashboard();
    pollTimer = setInterval(refreshDashboard, POLL_MS);
  } else if (route === "rules") {
    refreshRules();
    pollTimer = setInterval(refreshRules, POLL_MS);
  } else if (route === "perf") {
    initPerf();
  } else if (route === "settings") {
    refreshSettings();
  } else if (route === "drilldown") {
    initDrilldown();
  }
  perf.record("renderRoute", performance.now() - tRoute, { route });
}

// ── route: dashboard ───────────────────────────────────────────────────

async function refreshDashboard() {
  const tAll = performance.now();
  const port = await getStatsPort();
  if (!port) { setConnection(false); return; }
  try {
    console.debug("fetching dashboard data from port", port);
    const [summary, categories] = await perf.timeAsync("refreshDashboard.fetchAll", () => Promise.all([
      /** @type {Promise<Summary>} */         (fetchJson(port, "/stats")),
      /** @type {Promise<CategoryCount[]>} */ (fetchJson(port, "/stats/categories")),
    ]));
    setConnection(true);
    renderCounter(document.getElementById("m-today"), summary.today);
    renderCounter(document.getElementById("m-7d"),    summary.last_7d);
    renderCounter(document.getElementById("m-30d"),   summary.last_30d);
    renderCounter(document.getElementById("m-total"), summary.total);
    const cats = document.getElementById("categories");
    if (cats) renderBars(cats, categories, "subcategory", "category", (i) => categoryClass(i.category));
    perf.record("refreshDashboard", performance.now() - tAll, { cats: categories.length });
  } catch (e) {
    setConnection(false);
    perf.record("refreshDashboard.error", performance.now() - tAll, { err: String(e) });
    console.warn("dashboard refresh failed:", e);
  }
}

// ── route: rules ───────────────────────────────────────────────────────

async function refreshRules() {
  const tAll = performance.now();
  const port = await getStatsPort();
  if (!port) { setConnection(false); return; }
  try {
    const rules = /** @type {RuleCount[]} */ (await fetchJson(port, "/stats/rules?limit=200"));
    setConnection(true);
    const el = document.getElementById("rules-list");
    if (el) renderBars(el, rules, "rule_id", null, () => "cat-other");
    perf.record("refreshRules", performance.now() - tAll, { rules: rules.length });
  } catch (e) {
    setConnection(false);
    perf.record("refreshRules.error", performance.now() - tAll, { err: String(e) });
    console.warn("rules refresh failed:", e);
  }
}

// ── route: perf ────────────────────────────────────────────────────────
//
// Pulls /perf snapshot and renders a sortable table. Click a column header
// to change sort. Click a row to expand a small detail block (share %,
// throughput estimate, raw numbers). Auto-refreshes every POLL_MS unless
// paused. Backend also writes /tmp/bleep-perf.{json,jsonl} on its own timer
// for offline/file-based debugging — independent of this UI.

const perfView = {
  rows: [],          // last fetched snapshot
  sortBy: "total_ms",
  sortDir: "desc",   // "asc" | "desc"
  filter: "",        // free-text / regex (case insensitive)
  expanded: new Set(),
  paused: false,
};

function initPerf() {
  const search = document.getElementById("perf-search");
  const pause = document.getElementById("perf-pause");
  const reset = document.getElementById("perf-reset");
  const tbody = document.getElementById("perf-body");
  if (search) {
    search.value = perfView.filter;
    search.addEventListener("input", () => {
      perfView.filter = search.value;
      drawPerf();
    });
  }
  if (pause) {
    pause.checked = perfView.paused;
    pause.addEventListener("change", () => { perfView.paused = pause.checked; });
  }
  if (reset) {
    reset.addEventListener("click", async () => {
      const port = await getStatsPort();
      if (!port) return;
      try { await fetchJson(port, "/perf?reset=1"); } catch (_) {}
      perfView.rows = [];
      perfView.expanded.clear();
      refreshPerf();
    });
  }
  // header sort
  document.querySelectorAll(".perf-table thead th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (perfView.sortBy === key) {
        perfView.sortDir = perfView.sortDir === "desc" ? "asc" : "desc";
      } else {
        perfView.sortBy = key;
        perfView.sortDir = key === "name" ? "asc" : "desc";
      }
      drawPerf();
    });
  });
  // row click → toggle expansion (delegated)
  if (tbody) {
    tbody.addEventListener("click", (ev) => {
      const tr = ev.target.closest("tr.perf-row");
      if (!tr) return;
      const name = tr.dataset.name;
      if (perfView.expanded.has(name)) perfView.expanded.delete(name);
      else perfView.expanded.add(name);
      drawPerf();
    });
  }
  refreshPerf();
  pollTimer = setInterval(() => { if (!perfView.paused) refreshPerf(); }, POLL_MS);
}

async function refreshPerf() {
  const tAll = performance.now();
  const port = await getStatsPort();
  if (!port) { setConnection(false); return; }
  try {
    const rows = await fetchJson(port, "/perf");
    setConnection(true);
    perfView.rows = Array.isArray(rows) ? rows : [];
    drawPerf();
    perf.record("refreshPerf", performance.now() - tAll, { rows: perfView.rows.length });
  } catch (e) {
    setConnection(false);
    perf.record("refreshPerf.error", performance.now() - tAll, { err: String(e) });
    console.warn("perf refresh failed:", e);
  }
}

function drawPerf() {
  const tbody = document.getElementById("perf-body");
  const counter = document.getElementById("perf-count");
  if (!tbody) return;

  // build filter predicate (try regex, fall back to substring)
  const q = perfView.filter.trim();
  let pred = () => true;
  if (q) {
    let re = null;
    try { re = new RegExp(q, "i"); } catch (_) { re = null; }
    pred = (name) => re ? re.test(name) : name.toLowerCase().includes(q.toLowerCase());
  }
  const filtered = perfView.rows.filter((r) => pred(r.name));
  const totalAll = perfView.rows.reduce((a, r) => a + (r.total_ms || 0), 0);

  // sort
  const dir = perfView.sortDir === "asc" ? 1 : -1;
  filtered.sort((a, b) => {
    const ka = a[perfView.sortBy];
    const kb = b[perfView.sortBy];
    if (ka === kb) return 0;
    if (typeof ka === "string") return ka.localeCompare(kb) * dir;
    return (ka < kb ? -1 : 1) * dir;
  });

  // sort indicator on headers
  document.querySelectorAll(".perf-table thead th[data-sort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === perfView.sortBy);
    th.classList.toggle("desc", th.dataset.sort === perfView.sortBy && perfView.sortDir === "desc");
    th.classList.toggle("asc",  th.dataset.sort === perfView.sortBy && perfView.sortDir === "asc");
  });

  if (counter) {
    counter.textContent = q
      ? `${filtered.length} / ${perfView.rows.length} spans (filtered)`
      : `${perfView.rows.length} spans`;
  }

  // render
  const fmt = (n, d = 2) => (n == null || !isFinite(n)) ? "—" : n.toLocaleString(undefined, { maximumFractionDigits: d });
  const maxTotal = filtered.reduce((m, r) => Math.max(m, r.total_ms || 0), 0) || 1;

  const html = filtered.map((r) => {
    const sharePct = totalAll > 0 ? (r.total_ms / totalAll) * 100 : 0;
    const barPct = (r.total_ms / maxTotal) * 100;
    const expanded = perfView.expanded.has(r.name);
    const expandedRow = expanded ? `
      <tr class="perf-detail">
        <td colspan="7">
          <div class="perf-detail-grid">
            <div><span class="dim">share of total</span><br><b>${fmt(sharePct)}%</b></div>
            <div><span class="dim">throughput</span><br><b>${fmt(r.count / Math.max(r.total_ms / 1000, 0.001))}/s</b></div>
            <div><span class="dim">avg ns</span><br><b>${fmt(r.avg_ms * 1e6, 0)}</b></div>
            <div><span class="dim">total s</span><br><b>${fmt(r.total_ms / 1000, 3)}</b></div>
            <div><span class="dim">count</span><br><b>${fmt(r.count, 0)}</b></div>
          </div>
        </td>
      </tr>` : "";
    return `
      <tr class="perf-row${expanded ? " expanded" : ""}" data-name="${escapeHtml(r.name)}">
        <td class="perf-col-name mono" title="${escapeHtml(r.name)}">${escapeHtml(r.name)}</td>
        <td class="perf-col-num">${fmt(r.count, 0)}</td>
        <td class="perf-col-num">${fmt(r.avg_ms)}</td>
        <td class="perf-col-num">${fmt(r.min_ms)}</td>
        <td class="perf-col-num">${fmt(r.max_ms)}</td>
        <td class="perf-col-num">${fmt(r.total_ms)}</td>
        <td class="perf-col-bar">
          <div class="perf-bar"><div class="perf-bar-fill" style="width:${barPct.toFixed(1)}%"></div></div>
        </td>
      </tr>${expandedRow}`;
  }).join("");

  tbody.innerHTML = html || `<tr><td colspan="7" class="empty">no spans recorded yet</td></tr>`;
}

// ── route: settings ────────────────────────────────────────────────────

async function refreshSettings() {
  const port = await getStatsPort();
  const portEl = document.getElementById("s-stats-port");
  const evPortEl = document.getElementById("s-events-port");
  const statusEl = document.getElementById("s-status");
  if (portEl) portEl.textContent = port ? `127.0.0.1:${port}` : "—";
  if (statusEl) statusEl.textContent = port ? "Connected" : "Not connected";
  // events port is read by the Rust side only — we surface its existence
  if (evPortEl) evPortEl.textContent = "(see /tmp/bleep-events.port)";
  setConnection(!!port);
  wireSettingsActions();
}

let settingsActionsWired = false;
function wireSettingsActions() {
  if (settingsActionsWired) return;
  const resetStats = document.getElementById("s-reset-stats");
  const resetPerf = document.getElementById("s-reset-perf");
  const resetDict = document.getElementById("s-reset-dict");
  const status = document.getElementById("s-reset-status");
  if (!resetStats || !resetPerf || !resetDict || !status) return;
  settingsActionsWired = true;

  const setStatus = (msg, kind) => {
    status.textContent = msg;
    status.classList.remove("ok", "err");
    if (kind) status.classList.add(kind);
  };

  // Two-click confirm: window.confirm() is a no-op in the Tauri webview
  // (no dialog plugin installed), so the action would silently never fire.
  // First click arms the button; second click within 4s actually runs.
  const armed = new WeakMap();
  const originalLabels = new WeakMap();
  const runReset = async (btn, path, confirmMsg, label) => {
    if (armed.get(btn) !== true) {
      if (!originalLabels.has(btn)) originalLabels.set(btn, btn.textContent);
      armed.set(btn, true);
      btn.classList.add("armed");
      btn.textContent = "Click again to confirm";
      setStatus(confirmMsg);
      const t = setTimeout(() => {
        armed.set(btn, false);
        btn.classList.remove("armed");
        btn.textContent = originalLabels.get(btn);
        setStatus("");
      }, 4000);
      btn._disarm = t;
      return;
    }
    clearTimeout(btn._disarm);
    armed.set(btn, false);
    btn.classList.remove("armed");
    btn.textContent = originalLabels.get(btn) ?? btn.textContent;
    const port = await getStatsPort();
    if (!port) { setStatus("gateway not connected", "err"); return; }
    btn.disabled = true;
    setStatus(`resetting ${label}…`);
    try {
      const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST" });
      if (!r.ok) throw new Error(`${r.status}`);
      const body = await r.json().catch(() => ({}));
      const extra = typeof body.deleted === "number" ? ` (${body.deleted} rows deleted)` : "";
      setStatus(`${label} reset${extra}`, "ok");
    } catch (e) {
      setStatus(`reset failed: ${e?.message || e}`, "err");
    } finally {
      btn.disabled = false;
    }
  };

  resetStats.addEventListener("click", () =>
    runReset(resetStats, "/stats/reset",
      "Wipe all redaction history? This cannot be undone.",
      "redaction history"));
  resetPerf.addEventListener("click", () =>
    runReset(resetPerf, "/perf/reset",
      "Reset all perf counters?",
      "perf counters"));
  resetDict.addEventListener("click", () =>
    runReset(resetDict, "/dictionary/reset",
      "Wipe the original→fake dictionary? New requests will mint fresh fakes.",
      "fake dictionary"));
}

// ── live tail (cross-route — appends only when dashboard is mounted) ──

/** @param {{ payload: ProxyEvent }} e */
function onRedactionEvent(e) {
  const tEvent = performance.now();
  if (activeRoute !== "dashboard") return;
  const tail = document.getElementById("tail");
  if (!tail) return;
  const empty = tail.querySelector(".empty");
  if (empty) empty.remove();

  const ev = e.payload;
  // ProxyEvent is tagged — only Request carries `redacted`. Response has no
  // redacted field at all, so guard on the discriminant.
  if (ev.type !== "Request") return;
  const redacted = ev.redacted ?? [];
  const redactedCount = redacted.length;
  const top = redacted
    .slice(0, 3)
    .map((r) => r.subcategory || r.category || r.rule_id)
    .join(", ");
  const summary = redactedCount > 0
    ? `${redactedCount} redacted${top ? ` (${escapeHtml(top)})` : ""}`
    : "";

  const item = document.createElement("div");
  item.className = "tail-item";
  const hasDetails = redactedCount > 0;
  // lazy-render: only build the inner table on first expand. With MAX_TAIL=1000
  // and events that can carry 60+ redactions each, eager-rendering every
  // details table at insert time blows up layout cost.
  item.innerHTML = `
    <div class="tail-row${hasDetails ? " expandable" : ""}">
      <span class="tail-caret">${hasDetails ? "▸" : ""}</span>
      <span class="tail-time">${fmtTime()}</span>
      <span class="tail-method">${escapeHtml(ev.method || "")}</span>
      <span class="tail-uri">${escapeHtml(ev.uri || "")}</span>
      <span class="tail-redactions">${summary}</span>
    </div>
    ${hasDetails ? `<div class="tail-details" hidden></div>` : ""}
  `;
  if (hasDetails) {
    tailEntries.set(item, redacted);
    const head = item.querySelector(".tail-row");
    const body = item.querySelector(".tail-details");
    const caret = item.querySelector(".tail-caret");
    head.addEventListener("click", () => {
      const open = body.hasAttribute("hidden");
      if (open && body.childElementCount === 0) {
        const entries = tailEntries.get(item);
        if (entries) body.innerHTML = renderRedactedDetails(entries);
      }
      body.toggleAttribute("hidden", !open);
      caret.textContent = open ? "▾" : "▸";
      head.classList.toggle("open", open);
    });
    // click any truncated cell to copy its full value to the clipboard.
    body.addEventListener("click", (ev) => {
      const code = ev.target.closest(".copyable");
      if (!code) return;
      ev.stopPropagation();
      const full = code.dataset.full ?? code.textContent ?? "";
      navigator.clipboard?.writeText(full).then(() => {
        code.classList.add("copied");
        setTimeout(() => code.classList.remove("copied"), 600);
      }).catch(() => {});
    });
  }
  // tag with searchable metadata so the client-side filter is a string match,
  // not a re-walk of the redacted entries on every keystroke.
  const cats = new Set();
  const rules = new Set();
  const haystackParts = [ev.method || "", ev.uri || ""];
  for (const r of redacted) {
    if (r.category) cats.add(r.category);
    if (r.rule_id) rules.add(r.rule_id);
    haystackParts.push(r.rule_id || "", r.subcategory || "", r.original || "", r.fake_value || "");
  }
  item.dataset.categories = [...cats].join(",");
  item.dataset.rules = [...rules].join(",");
  item.dataset.haystack = haystackParts.join(" ").toLowerCase();
  applyTailFilterTo(item);

  tail.prepend(item);
  while (tail.children.length > MAX_TAIL) tail.lastChild.remove();

  tailRowsEmitted += 1;
  const counter = document.getElementById("tail-counter");
  if (counter) counter.textContent = `· ${tailRowsEmitted} events`;
  updateTailMatchCount();
  perf.record("onRedactionEvent", performance.now() - tEvent, { redacted: redactedCount });
}

// returns true if a single tail-item passes the current filter.
function tailItemMatches(item) {
  if (tailFilter.cat !== "all") {
    const cats = (item.dataset.categories || "").split(",");
    if (!cats.includes(tailFilter.cat)) return false;
  }
  if (tailFilter.q) {
    const hay = item.dataset.haystack || "";
    if (!hay.includes(tailFilter.q)) return false;
  }
  return true;
}

// hides/shows one item without touching the rest. Called both per-item on
// insert (cheap) and via applyTailFilter for full re-walk on filter change.
function applyTailFilterTo(item) {
  item.classList.toggle("hidden-by-filter", !tailItemMatches(item));
}

function applyTailFilter() {
  const tail = document.getElementById("tail");
  if (!tail) return;
  for (const item of tail.querySelectorAll(".tail-item")) applyTailFilterTo(item);
  updateTailMatchCount();
}

function updateTailMatchCount() {
  const tail = document.getElementById("tail");
  const counter = document.getElementById("tail-counter");
  const matchOut = document.getElementById("tail-match-count");
  if (!tail) return;
  const total = tail.querySelectorAll(".tail-item").length;
  const filtered = tailFilter.q !== "" || tailFilter.cat !== "all";
  if (counter) {
    if (filtered) {
      const visible = tail.querySelectorAll(".tail-item:not(.hidden-by-filter)").length;
      counter.textContent = `· ${visible} / ${tailRowsEmitted} events`;
    } else {
      counter.textContent = `· ${tailRowsEmitted} events`;
    }
  }
  // the inline match badge is redundant with the header counter once we wire
  // both — keep it but trim it to a short ratio so the row stays compact.
  if (matchOut) {
    matchOut.textContent = filtered
      ? `${tail.querySelectorAll(".tail-item:not(.hidden-by-filter)").length} match`
      : "";
  }
}

function bindTailFilterControls() {
  const search = document.getElementById("tail-search");
  if (search && !search.dataset.bound) {
    search.dataset.bound = "1";
    search.addEventListener("input", () => {
      tailFilter.q = search.value.trim().toLowerCase();
      applyTailFilter();
    });
  }
  const chips = document.getElementById("tail-chips");
  if (chips && !chips.dataset.bound) {
    chips.dataset.bound = "1";
    chips.addEventListener("click", (e) => {
      const btn = e.target.closest(".chip");
      if (!btn) return;
      tailFilter.cat = btn.dataset.cat || "all";
      for (const c of chips.querySelectorAll(".chip")) {
        c.classList.toggle("active", c === btn);
      }
      applyTailFilter();
    });
  }
}

// ── route: drilldown (historical /redactions query) ───────────────────

function openDrilldown(filter) {
  const t = performance.now();
  drilldown.filter = { ...filter };
  drilldown.rows = [];
  drilldown.cursor = null;
  drilldown.loadedFirstPage = false;
  drilldown.loading = false;
  drilldown.groups = new Map();
  drilldown.expandedGroups = new Set();
  // force a re-render even if we're already on drilldown
  activeRoute = null;
  navigateTo("drilldown");
  perf.record("openDrilldown", performance.now() - t, filter);
}

function drilldownTitle() {
  const f = drilldown.filter;
  if (f.rule_id) return `Rule · ${f.rule_id}`;
  if (f.category && f.subcategory) return `${f.subcategory} / ${f.category}`;
  if (f.category) return f.category;
  return "Redactions";
}

function drilldownUrl() {
  const f = drilldown.filter;
  const p = new URLSearchParams();
  if (f.category)   p.set("category",    f.category);
  if (f.subcategory) p.set("subcategory", f.subcategory);
  if (f.rule_id)    p.set("rule_id",     f.rule_id);
  if (f.q)          p.set("q",           f.q);
  if (f.since != null) p.set("since", String(f.since));
  if (f.until != null) p.set("until", String(f.until));
  if (drilldown.cursor) p.set("cursor", drilldown.cursor);
  p.set("limit", "200");
  return `/redactions?${p.toString()}`;
}

async function loadDrilldownPage() {
  if (drilldown.loading) return;
  // cursor null after first load = exhausted
  if (drilldown.loadedFirstPage && drilldown.cursor === null) return;
  drilldown.loading = true;
  const tPage = performance.now();
  const sentinel = document.getElementById("dd-sentinel");
  if (sentinel) sentinel.textContent = "loading…";
  const port = await getStatsPort();
  if (!port) { if (sentinel) sentinel.textContent = "no gateway"; drilldown.loading = false; return; }
  try {
    /** @type {RedactedPage} */
    const page = await fetchJson(port, drilldownUrl());
    drilldown.rows = drilldown.rows.concat(page.rows);
    drilldown.cursor = page.next_cursor;
    drilldown.loadedFirstPage = true;
    appendDrilldownRows(page.rows);
    if (sentinel) {
      sentinel.textContent = drilldown.cursor === null
        ? (drilldown.rows.length === 0 ? "no matches" : `— end · ${drilldown.rows.length} rows —`)
        : "scroll for more…";
    }
    perf.record("loadDrilldownPage", performance.now() - tPage, { rows: page.rows.length, total: drilldown.rows.length });
  } catch (e) {
    if (sentinel) sentinel.textContent = `load failed: ${e}`;
    perf.record("loadDrilldownPage.error", performance.now() - tPage, { err: String(e) });
  } finally {
    drilldown.loading = false;
  }
}

/** @param {RedactedRow[]} rows */
function appendDrilldownRows(rows) {
  const t = performance.now();

  // always update groups map regardless of view mode
  for (const r of rows) {
    const key = r.original || "";
    let g = drilldown.groups.get(key);
    if (!g) {
      g = {
        original: key,
        fake: r.fake_value || "",
        rule_id: r.rule_id || "",
        category: r.category || "",
        subcategory: r.subcategory || "",
        count: 0,
        firstSeen: r.ts,
        lastSeen: r.ts,
        rows: [],
      };
      drilldown.groups.set(key, g);
    }
    g.count++;
    if (r.ts < g.firstSeen) g.firstSeen = r.ts;
    if (r.ts > g.lastSeen)  g.lastSeen  = r.ts;
    g.rows.push(r);
  }

  if (drilldown.viewMode === "flat") {
    const body = document.getElementById("dd-body");
    if (body) {
      body.insertAdjacentHTML("beforeend", buildFlatHtml(rows));
      applyColumnFilters();
    }
  } else {
    renderGroupedView();
  }

  perf.record("appendDrilldownRows", performance.now() - t, { rows: rows.length, mode: drilldown.viewMode });
}

/** Build HTML for flat table rows from an array of RedactedRow */
function buildFlatHtml(rows) {
  return rows.map((r) => {
    const time = fmtTime(new Date(r.ts * 1000));
    const cat  = r.category || "";
    const rule = r.rule_id  || "";
    const sub  = r.subcategory || "";
    const orig = r.original   || "";
    const fake = r.fake_value || "";
    return `
    <tr
      data-time="${escapeHtml(time)}"
      data-category="${escapeHtml(cat)}"
      data-rule="${escapeHtml(rule)}"
      data-subcategory="${escapeHtml(sub)}"
      data-original="${escapeHtml(orig.toLowerCase())}"
      data-fake="${escapeHtml(fake.toLowerCase())}">
      <td class="td-time">${escapeHtml(time)}</td>
      <td><span class="pill ${categoryClass(cat)}">${escapeHtml(cat)}</span></td>
      <td class="td-rule">${escapeHtml(rule)}</td>
      <td>${escapeHtml(sub)}</td>
      ${renderCopyCell(orig, "td-original")}
      ${renderCopyCell(fake, "td-fake")}
    </tr>`;
  }).join("");
}

/** Render the grouped list from drilldown.groups, applying colFilters. */
function renderGroupedView() {
  const container = document.getElementById("dd-grouped-list");
  if (!container) return;

  const origQ = (drilldown.colFilters.original || "").toLowerCase();
  const ruleQ = (drilldown.colFilters.rule     || "").toLowerCase();
  const catQ  = (drilldown.colFilters.category || "").toLowerCase();
  const subQ  = (drilldown.colFilters.subcategory || "").toLowerCase();

  let groups = [...drilldown.groups.values()];
  if (origQ) groups = groups.filter(g => g.original.toLowerCase().includes(origQ));
  if (ruleQ) groups = groups.filter(g => g.rule_id.toLowerCase().includes(ruleQ));
  if (catQ)  groups = groups.filter(g => g.category.toLowerCase().includes(catQ));
  if (subQ)  groups = groups.filter(g => g.subcategory.toLowerCase().includes(subQ));
  groups.sort((a, b) => b.count - a.count);

  if (groups.length === 0) {
    container.innerHTML = '<div class="empty">no matches</div>';
    updateDrilldownCount(0, 0);
    return;
  }

  const html = groups.map(g => {
    const isOpen = drilldown.expandedGroups.has(g.original);
    const catClass = categoryClass(g.category);
    const { display: origDisp, truncated: origTrunc } = truncate(g.original, 52);

    // time badge: single timestamp or range
    let timeBadge;
    if (g.firstSeen === g.lastSeen) {
      timeBadge = fmtTime(new Date(g.lastSeen * 1000));
    } else {
      const d1 = new Date(g.firstSeen * 1000);
      const d2 = new Date(g.lastSeen  * 1000);
      const sameDay = d1.toDateString() === d2.toDateString();
      timeBadge = sameDay
        ? `${fmtTime(d1)} – ${fmtTime(d2)}`
        : `${d1.toLocaleDateString([], { month: "short", day: "numeric" })} – ${fmtTime(d2)}`;
    }

    let subRowsHtml = "";
    if (isOpen) {
      subRowsHtml = g.rows.map(r => {
        const { display: fakeDisp } = truncate(r.fake_value || "", 44);
        return `<div class="dd-subrow">
          <span class="td-time">${escapeHtml(fmtTime(new Date(r.ts * 1000)))}</span>
          <span class="dd-subrow-arrow">→</span>
          <code class="copyable dd-subrow-fake" data-full="${escapeHtml(r.fake_value || "")}" title="${escapeHtml(r.fake_value || "")}">${escapeHtml(fakeDisp)}</code>
        </div>`;
      }).join("");
    }

    return `<div class="dd-group${isOpen ? " dd-group--open" : ""}" data-key="${escapeHtml(g.original)}">
      <div class="dd-group-row">
        <span class="dd-group-count">×${g.count}</span>
        <code class="dd-group-orig copyable${origTrunc ? " truncated" : ""}"
              data-full="${escapeHtml(g.original)}"
              title="${escapeHtml(g.original)}">${escapeHtml(origDisp)}</code>
        <span class="pill ${catClass} dd-group-pill">${escapeHtml(g.subcategory || g.category)}</span>
        <span class="dd-group-rule">${escapeHtml(g.rule_id)}</span>
        <span class="td-time dd-group-time">${escapeHtml(timeBadge)}</span>
        <span class="dd-group-caret">${isOpen ? "▾" : "▸"}</span>
      </div>
      ${isOpen ? `<div class="dd-subrows">${subRowsHtml}</div>` : ""}
    </div>`;
  }).join("");

  container.innerHTML = html;

  // delegated click: expand/collapse + copy (bind once; innerHTML replaces children, not container)
  if (!container.dataset.clickBound) {
    container.dataset.clickBound = "1";
    container.addEventListener("click", (e) => {
      // copy handler has priority
      const code = e.target.closest(".copyable");
      if (code) {
        e.stopPropagation();
        const full = code.dataset.full ?? code.textContent ?? "";
        navigator.clipboard?.writeText(full).then(() => {
          code.classList.add("copied");
          setTimeout(() => code.classList.remove("copied"), 600);
        }).catch(() => {});
        return;
      }
      // expand / collapse group
      const group = e.target.closest(".dd-group");
      if (!group) return;
      const key = group.dataset.key;
      if (drilldown.expandedGroups.has(key)) drilldown.expandedGroups.delete(key);
      else drilldown.expandedGroups.add(key);
      renderGroupedView();
    });
  }

  updateDrilldownCount(groups.length, drilldown.groups.size);
}

function updateDrilldownCount(visibleGroups, totalGroups) {
  const el = document.getElementById("dd-count");
  if (!el) return;
  const more = drilldown.cursor === null ? "" : "+";
  if (drilldown.viewMode === "grouped") {
    const total = drilldown.rows.length;
    if (visibleGroups != null && visibleGroups !== totalGroups) {
      el.textContent = `${visibleGroups} / ${totalGroups} groups · ${total}${more} events`;
    } else {
      el.textContent = `${totalGroups != null ? totalGroups : drilldown.groups.size} groups · ${total}${more} events`;
    }
  } else {
    el.textContent = `${drilldown.rows.length}${more} rows`;
  }
}

// hide rows whose data-* attributes don't match every active per-column
// filter. In grouped mode the filter re-renders the grouped list instead.
function applyColumnFilters() {
  if (drilldown.viewMode === "grouped") {
    renderGroupedView();
    return;
  }
  const body = document.getElementById("dd-body");
  if (!body) return;
  const f = drilldown.colFilters;
  const active = Object.entries(f).filter(([_, v]) => v && v.length > 0);
  let visible = 0, total = 0;
  for (const tr of body.children) {
    total++;
    let hide = false;
    for (const [col, needle] of active) {
      const hay = (tr.dataset[col] || "").toLowerCase();
      if (!hay.includes(needle)) { hide = true; break; }
    }
    tr.style.display = hide ? "none" : "";
    if (!hide) visible++;
  }
  const counter = document.getElementById("dd-count");
  if (counter) {
    const more = drilldown.cursor === null ? "" : "+";
    counter.textContent = active.length > 0
      ? `${visible} / ${total}${more} rows (filtered)`
      : `${total}${more} rows`;
  }
}

function initDrilldown() {
  const title    = document.getElementById("dd-title");
  const sub      = document.getElementById("dd-subtitle");
  const back     = document.getElementById("dd-back");
  const search   = document.getElementById("dd-search");
  const wrap     = document.getElementById("dd-wrap");
  const body     = document.getElementById("dd-body");
  const grouped  = document.getElementById("dd-grouped-list");

  if (title) title.textContent = drilldownTitle();
  if (sub) {
    const f = drilldown.filter;
    sub.textContent = `historical redactions${f.q ? ` matching "${f.q}"` : ""}`;
  }
  if (body)    body.innerHTML    = "";
  if (grouped) grouped.innerHTML = "";

  // apply current view mode class to the wrap
  if (wrap) {
    wrap.classList.toggle("dd-mode-grouped", drilldown.viewMode === "grouped");
    wrap.classList.toggle("dd-mode-flat",    drilldown.viewMode === "flat");
  }

  // ── view mode toggle ────────────────────────────────────────────────
  const groupedBtn = document.getElementById("dd-view-grouped");
  const flatBtn    = document.getElementById("dd-view-flat");
  const setViewMode = (mode) => {
    drilldown.viewMode = mode;
    groupedBtn?.classList.toggle("active", mode === "grouped");
    flatBtn?.classList.toggle("active",    mode === "flat");
    wrap?.classList.toggle("dd-mode-grouped", mode === "grouped");
    wrap?.classList.toggle("dd-mode-flat",    mode === "flat");
    if (mode === "grouped") {
      renderGroupedView();
    } else {
      // rebuild flat view from accumulated rows
      if (body) {
        body.innerHTML = buildFlatHtml(drilldown.rows);
        applyColumnFilters();
      }
      updateDrilldownCount();
    }
  };
  groupedBtn?.addEventListener("click", () => setViewMode("grouped"));
  flatBtn?.addEventListener("click",    () => setViewMode("flat"));

  // ── global search (re-fetches from server) ─────────────────────────
  if (search) {
    search.value = drilldown.filter.q || "";
    let t;
    search.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        drilldown.filter.q = search.value.trim() || undefined;
        _resetAndReload();
      }, 200);
    });
  }

  if (back) back.addEventListener("click", () => navigateTo("dashboard"));

  // ── per-column filters (client-side) ───────────────────────────────
  document.querySelectorAll(".dd-colfilter").forEach((input) => {
    const col = input.dataset.col;
    input.value = (drilldown.colFilters && drilldown.colFilters[col]) || "";
    let t;
    input.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        drilldown.colFilters[col] = input.value.trim().toLowerCase();
        applyColumnFilters();
      }, 80);
    });
  });

  // ── date range filter ──────────────────────────────────────────────
  const dateFrom    = document.getElementById("dd-date-from");
  const dateTo      = document.getElementById("dd-date-to");
  const quickDates  = document.getElementById("dd-quick-dates");

  // restore datetime inputs from existing filter state
  if (dateFrom && drilldown.filter.since != null)
    dateFrom.value = _tsToDatetimeLocal(drilldown.filter.since);
  if (dateTo && drilldown.filter.until != null)
    dateTo.value = _tsToDatetimeLocal(drilldown.filter.until);

  if (dateFrom) {
    dateFrom.addEventListener("change", () => {
      drilldown.filter.since = dateFrom.value ? _datetimeLocalToTs(dateFrom.value) : null;
      _clearQuickActive();
      _resetAndReload();
    });
  }
  if (dateTo) {
    dateTo.addEventListener("change", () => {
      drilldown.filter.until = dateTo.value ? _datetimeLocalToTs(dateTo.value) : null;
      _clearQuickActive();
      _resetAndReload();
    });
  }
  if (quickDates) {
    // mark initial active preset
    if (drilldown.filter.since == null && drilldown.filter.until == null) {
      quickDates.querySelector('[data-preset="all"]')?.classList.add("active");
    }
    quickDates.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-preset]");
      if (!btn) return;
      _clearQuickActive();
      btn.classList.add("active");
      const now     = Math.floor(Date.now() / 1000);
      const midnightMs = new Date().setHours(0, 0, 0, 0);
      const midnight   = Math.floor(midnightMs / 1000);
      switch (btn.dataset.preset) {
        case "all":
          drilldown.filter.since = null;
          drilldown.filter.until = null;
          if (dateFrom) dateFrom.value = "";
          if (dateTo)   dateTo.value   = "";
          break;
        case "today":
          drilldown.filter.since = midnight;
          drilldown.filter.until = null;
          if (dateFrom) dateFrom.value = _tsToDatetimeLocal(midnight);
          if (dateTo)   dateTo.value   = "";
          break;
        case "7d":
          drilldown.filter.since = midnight - 6 * 86400;
          drilldown.filter.until = null;
          if (dateFrom) dateFrom.value = _tsToDatetimeLocal(midnight - 6 * 86400);
          if (dateTo)   dateTo.value   = "";
          break;
        case "30d":
          drilldown.filter.since = midnight - 29 * 86400;
          drilldown.filter.until = null;
          if (dateFrom) dateFrom.value = _tsToDatetimeLocal(midnight - 29 * 86400);
          if (dateTo)   dateTo.value   = "";
          break;
      }
      _resetAndReload();
    });
  }

  // ── infinite scroll ────────────────────────────────────────────────
  if (wrap) {
    wrap.addEventListener("scroll", () => {
      const remaining = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight;
      if (remaining < 200) loadDrilldownPage();
    });
    // copy-on-click for truncated cells in flat view
    wrap.addEventListener("click", (ev) => {
      if (drilldown.viewMode !== "flat") return;
      const code = ev.target.closest(".copyable");
      if (!code) return;
      ev.stopPropagation();
      const full = code.dataset.full ?? code.textContent ?? "";
      navigator.clipboard?.writeText(full).then(() => {
        code.classList.add("copied");
        setTimeout(() => code.classList.remove("copied"), 600);
      }).catch(() => {});
    });
  }

  loadDrilldownPage();
}

// ── drilldown internal helpers ─────────────────────────────────────────

function _resetAndReload() {
  drilldown.rows = [];
  drilldown.cursor = null;
  drilldown.loadedFirstPage = false;
  drilldown.groups = new Map();
  drilldown.expandedGroups = new Set();
  const body    = document.getElementById("dd-body");
  const grouped = document.getElementById("dd-grouped-list");
  if (body)    body.innerHTML    = "";
  if (grouped) grouped.innerHTML = "";
  loadDrilldownPage();
}

function _clearQuickActive() {
  document.querySelectorAll("#dd-quick-dates [data-preset]")
    .forEach(b => b.classList.remove("active"));
}

function _tsToDatetimeLocal(ts) {
  // format unix ts as "YYYY-MM-DDTHH:mm" for datetime-local input value
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function _datetimeLocalToTs(val) {
  return Math.floor(new Date(val).getTime() / 1000);
}

listen("redaction", onRedactionEvent).catch((err) =>
  console.warn("listen failed:", err)
);

// ── boot ───────────────────────────────────────────────────────────────

window.addEventListener("hashchange", () => renderRoute(currentRoute()));
window.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "r") {
    e.preventDefault();
    location.reload();
  }
});
renderRoute(currentRoute());
