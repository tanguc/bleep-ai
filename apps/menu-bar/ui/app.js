// Bleep dashboard — vanilla JS, no bundler.
// - polls the local /stats endpoint for aggregations
// - listens to Tauri events for live tail (forwarded by the rust side
//   from the existing event_bus TCP stream)

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const POLL_MS = 2000;
const MAX_TAIL = 100;

const els = {
  conn: document.getElementById("connection"),
  today: document.getElementById("m-today"),
  d7: document.getElementById("m-7d"),
  d30: document.getElementById("m-30d"),
  total: document.getElementById("m-total"),
  cats: document.getElementById("categories"),
  rules: document.getElementById("rules"),
  tail: document.getElementById("tail"),
  tailCount: document.getElementById("tail-counter"),
};

let tailRowsEmitted = 0;

async function getStatsPort() {
  try {
    return await invoke("get_stats_port");
  } catch (_) {
    return null;
  }
}

async function fetchJson(port, path) {
  const r = await fetch(`http://127.0.0.1:${port}${path}`);
  if (!r.ok) throw new Error(`${path} ${r.status}`);
  return r.json();
}

function setConnection(connected) {
  els.conn.textContent = connected ? "● connected" : "○ disconnected";
  els.conn.classList.toggle("connected", connected);
  els.conn.classList.toggle("disconnected", !connected);
}

function renderCounter(el, value) {
  // tiny number animation for delight without overdoing it
  if (el.textContent === String(value)) return;
  el.textContent = value;
  el.animate(
    [{ transform: "scale(1.08)" }, { transform: "scale(1)" }],
    { duration: 220, easing: "ease-out" }
  );
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
  const html = items
    .map((i) => {
      const pct = max > 0 ? Math.round((i.count / max) * 100) : 0;
      const klass = classKey ? classKey(i) : "cat-other";
      const label = secondaryKey
        ? `<span class="bar-label">${escapeHtml(i[labelKey])} <span class="dim">/ ${escapeHtml(i[secondaryKey])}</span></span>`
        : `<span class="bar-label">${escapeHtml(i[labelKey])}</span>`;
      return `<div class="bar ${klass}" style="--bar-pct: ${pct}%">${label}<span class="bar-count">${i.count}</span></div>`;
    })
    .join("");
  container.innerHTML = html;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(d = new Date()) {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function appendTailRow(ev) {
  // remove the empty placeholder once we have real data
  const empty = els.tail.querySelector(".empty");
  if (empty) empty.remove();

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
  els.tail.prepend(row);

  // cap memory
  while (els.tail.children.length > MAX_TAIL) els.tail.lastChild.remove();

  tailRowsEmitted += 1;
  els.tailCount.textContent = `· ${tailRowsEmitted} events`;
}

async function refresh() {
  const port = await getStatsPort();
  if (!port) {
    setConnection(false);
    return;
  }
  try {
    const [summary, categories, rules] = await Promise.all([
      fetchJson(port, "/stats"),
      fetchJson(port, "/stats/categories"),
      fetchJson(port, "/stats/rules?limit=20"),
    ]);
    setConnection(true);
    renderCounter(els.today, summary.last_24h);
    renderCounter(els.d7,    summary.last_7d);
    renderCounter(els.d30,   summary.last_30d);
    renderCounter(els.total, summary.total);
    renderBars(els.cats, categories, "subcategory", "category", (i) => categoryClass(i.category));
    renderBars(els.rules, rules, "rule_id", null, () => "cat-other");
  } catch (e) {
    setConnection(false);
    console.warn("refresh failed:", e);
  }
}

// live tail: rust side forwards event_bus messages as Tauri "redaction" events
listen("redaction", (e) => {
  appendTailRow(e.payload);
}).catch((err) => console.warn("listen failed:", err));

// initial + periodic poll
refresh();
setInterval(refresh, POLL_MS);
