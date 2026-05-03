// Bleep desktop app — hash-routed SPA. No bundler, no framework.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const POLL_MS = 2000;
const MAX_TAIL = 100;

const ROUTES = ["dashboard", "rules", "settings"];
const DEFAULT_ROUTE = "dashboard";

let activeRoute = null;
let pollTimer = null;
let statsPort = null;
let tailRowsEmitted = 0;

// ── helpers ────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(d = new Date()) {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

async function getStatsPort() {
  if (statsPort) return statsPort;
  try {
    statsPort = await invoke("get_stats_port");
    return statsPort;
  } catch (_) { return null; }
}

async function fetchJson(port, path) {
  const r = await fetch(`http://127.0.0.1:${port}${path}`);
  if (!r.ok) throw new Error(`${path} ${r.status}`);
  return r.json();
}

function setConnection(connected) {
  const el = document.getElementById("connection");
  if (!el) return;
  el.textContent = connected ? "● connected" : "○ disconnected";
  el.classList.toggle("connected", connected);
  el.classList.toggle("disconnected", !connected);
}

function categoryClass(category) {
  if (category === "secret") return "cat-secret";
  if (category === "pii") return "cat-pii";
  if (category === "infra") return "cat-infra";
  return "cat-other";
}

function renderBars(container, items, labelKey, secondaryKey, classKey) {
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="empty">no redactions yet</div>';
    return;
  }
  const max = Math.max(...items.map((i) => i.count));
  const html = items.map((i) => {
    const pct = max > 0 ? Math.round((i.count / max) * 100) : 0;
    const klass = classKey ? classKey(i) : "cat-other";
    const label = secondaryKey
      ? `<span class="bar-label">${escapeHtml(i[labelKey])} <span class="dim">/ ${escapeHtml(i[secondaryKey])}</span></span>`
      : `<span class="bar-label">${escapeHtml(i[labelKey])}</span>`;
    return `<div class="bar ${klass}" style="--bar-pct: ${pct}%">${label}<span class="bar-count">${i.count}</span></div>`;
  }).join("");
  container.innerHTML = html;
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
  if (activeRoute === route) return;
  activeRoute = route;
  highlightSidebar(route);

  const tpl = document.getElementById(`route-${route}`);
  const content = document.getElementById("content");
  content.innerHTML = "";
  if (tpl) content.appendChild(tpl.content.cloneNode(true));

  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (route === "dashboard") {
    refreshDashboard();
    pollTimer = setInterval(refreshDashboard, POLL_MS);
  } else if (route === "rules") {
    refreshRules();
    pollTimer = setInterval(refreshRules, POLL_MS);
  } else if (route === "settings") {
    refreshSettings();
  }
}

// ── route: dashboard ───────────────────────────────────────────────────

async function refreshDashboard() {
  const port = await getStatsPort();
  if (!port) { setConnection(false); return; }
  try {
    const [summary, categories, rules] = await Promise.all([
      fetchJson(port, "/stats"),
      fetchJson(port, "/stats/categories"),
      fetchJson(port, "/stats/rules?limit=10"),
    ]);
    setConnection(true);
    renderCounter(document.getElementById("m-today"), summary.last_24h);
    renderCounter(document.getElementById("m-7d"),    summary.last_7d);
    renderCounter(document.getElementById("m-30d"),   summary.last_30d);
    renderCounter(document.getElementById("m-total"), summary.total);
    const cats = document.getElementById("categories");
    const rs = document.getElementById("rules");
    if (cats) renderBars(cats, categories, "subcategory", "category", (i) => categoryClass(i.category));
    if (rs)   renderBars(rs, rules, "rule_id", null, () => "cat-other");
  } catch (e) {
    setConnection(false);
    console.warn("dashboard refresh failed:", e);
  }
}

// ── route: rules ───────────────────────────────────────────────────────

async function refreshRules() {
  const port = await getStatsPort();
  if (!port) { setConnection(false); return; }
  try {
    const rules = await fetchJson(port, "/stats/rules?limit=200");
    setConnection(true);
    const el = document.getElementById("rules-list");
    if (el) renderBars(el, rules, "rule_id", null, () => "cat-other");
  } catch (e) {
    setConnection(false);
    console.warn("rules refresh failed:", e);
  }
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
}

// ── live tail (cross-route — appends only when dashboard is mounted) ──

listen("redaction", (e) => {
  if (activeRoute !== "dashboard") return;
  const tail = document.getElementById("tail");
  if (!tail) return;
  const empty = tail.querySelector(".empty");
  if (empty) empty.remove();

  const ev = e.payload;
  const redactedCount = (ev.redacted || []).length;
  const top = (ev.redacted || [])
    .slice(0, 3)
    .map((r) => r.subcategory || r.category || r.rule_id)
    .join(", ");
  const summary = redactedCount > 0
    ? `${redactedCount} redacted${top ? ` (${escapeHtml(top)})` : ""}`
    : "";

  const row = document.createElement("div");
  row.className = "tail-row";
  row.innerHTML = `
    <span class="tail-time">${fmtTime()}</span>
    <span class="tail-method">${escapeHtml(ev.method || "")}</span>
    <span class="tail-uri">${escapeHtml(ev.uri || "")}</span>
    <span class="tail-redactions">${summary}</span>
  `;
  tail.prepend(row);
  while (tail.children.length > MAX_TAIL) tail.lastChild.remove();

  tailRowsEmitted += 1;
  const counter = document.getElementById("tail-counter");
  if (counter) counter.textContent = `· ${tailRowsEmitted} events`;
}).catch((err) => console.warn("listen failed:", err));

// ── boot ───────────────────────────────────────────────────────────────

window.addEventListener("hashchange", () => renderRoute(currentRoute()));
renderRoute(currentRoute());
