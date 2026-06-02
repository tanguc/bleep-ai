//! Local HTTP server that exposes redaction stats from the SQLite history DB.
//!
//! Bound to 127.0.0.1 only — never listens on a public interface. Routes:
//!   GET /health             -> { "status": "ok" }
//!   GET /stats              -> Summary { total, today, last_7d, last_30d }
//!   GET /stats/categories   -> [ { category, subcategory, count }, ... ]
//!   GET /stats/rules?limit  -> [ { rule_id, count }, ... ]   (limit default: 20)
//!
//! Live updates are not served here — the menu-bar app subscribes to the
//! existing TCP event_bus (port discovered via /tmp/bleep-events.port).
//!
//! The bound port is written to /tmp/bleep-stats.port for the Tauri app to
//! discover. Mirrors the event_bus startup pattern.

use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

use crate::stats;

// Small helper so every handler logs its wall time + a one-line summary.
// Keep it side-effecting (eprintln) — nothing fancy, easy to grep.
fn log_timing(route: &str, t0: Instant, extra: &str) {
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[stats_server] {route} {ms:.1}ms {extra}");
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Deserialize)]
struct RulesQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct RedactionsQuery {
    category: Option<String>,
    subcategory: Option<String>,
    rule_id: Option<String>,
    request_id: Option<String>,
    q: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn get_summary() -> Json<stats::Summary> {
    let t0 = Instant::now();
    let s = stats::summary();
    log_timing("GET /stats", t0, &format!("total={}", s.total));
    Json(s)
}

async fn get_categories() -> Json<Vec<stats::CategoryCount>> {
    let t0 = Instant::now();
    let v = stats::by_category();
    log_timing("GET /stats/categories", t0, &format!("rows={}", v.len()));
    Json(v)
}

async fn get_rules(Query(q): Query<RulesQuery>) -> Json<Vec<stats::RuleCount>> {
    let t0 = Instant::now();
    let limit = q.limit.unwrap_or(20).clamp(1, 1000);
    let v = stats::top_rules(limit);
    log_timing(
        "GET /stats/rules",
        t0,
        &format!("limit={limit} rows={}", v.len()),
    );
    Json(v)
}

/// Drill-down endpoint — returns full redaction rows including originals.
/// SECURITY: this exposes originals over loopback HTTP. Today the server is
/// bound to 127.0.0.1 so the OS is the trust boundary; if that ever changes,
/// gate this route behind an env flag (see stats/mod.rs doc comment).
async fn get_redactions(
    Query(q): Query<RedactionsQuery>,
) -> Json<bleep_events::RedactedPage> {
    let t0 = Instant::now();
    let filter = stats::RedactionFilter {
        category: q.category.clone(),
        subcategory: q.subcategory.clone(),
        rule_id: q.rule_id.clone(),
        request_id: q.request_id,
        q: q.q.clone(),
        since: q.since,
        until: q.until,
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let (rows, next_cursor) = stats::query_redactions(&filter, limit, q.cursor.as_deref());
    log_timing(
        "GET /redactions",
        t0,
        &format!(
            "rows={} limit={} cat={:?} sub={:?} rule={:?} q={:?} cursor={}",
            rows.len(),
            limit,
            q.category,
            q.subcategory,
            q.rule_id,
            q.q,
            q.cursor.is_some()
        ),
    );
    Json(bleep_events::RedactedPage { rows, next_cursor })
}

#[derive(Serialize)]
struct RulesCount {
    count: usize,
}

/// GET /rules/count — number of loaded patterns. Cheap accessor that lets
/// the claude-wrapper banner show the rule count without needing the on-disk
/// rules file (which it may not be able to find from the install dir).
async fn get_rules_count() -> Json<RulesCount> {
    Json(RulesCount {
        count: crate::patterns::RULES.len(),
    })
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

#[derive(Serialize)]
struct ResetResp {
    deleted: u64,
}

/// POST /stats/reset — wipe redaction history. Loopback-only, no auth.
async fn post_stats_reset() -> Json<ResetResp> {
    let t0 = Instant::now();
    let deleted = stats::reset_all();
    log_timing("POST /stats/reset", t0, &format!("deleted={deleted}"));
    Json(ResetResp { deleted })
}

#[derive(Serialize)]
struct PerfResetResp {
    ok: bool,
}

/// POST /perf/reset — zero in-memory perf counters.
async fn post_perf_reset() -> Json<PerfResetResp> {
    crate::perf::reset();
    Json(PerfResetResp { ok: true })
}

/// POST /dictionary/reset — wipe the persistent fake-dictionary (originals →
/// fakes). Loopback-only, no auth. Returns the number of rows deleted.
async fn post_dictionary_reset() -> Json<ResetResp> {
    let t0 = Instant::now();
    let deleted = crate::dictionary::reset_all();
    log_timing("POST /dictionary/reset", t0, &format!("deleted={deleted}"));
    Json(ResetResp { deleted })
}

// ── admin: enable / disable ────────────────────────────────────────────────
// The disabled flag lives at ~/.bleep/disabled. When present the wrapper
// skips proxy setup on every claude invocation (persistent bypass mode).
// These endpoints let the GUI toggle the flag without a shell command.

fn disabled_flag_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".bleep").join("disabled")
}

#[derive(Serialize)]
struct EnabledResp {
    enabled: bool,
}

/// GET /admin/enabled — returns whether bleep is currently active.
async fn get_admin_enabled() -> Json<EnabledResp> {
    Json(EnabledResp { enabled: !disabled_flag_path().exists() })
}

/// POST /admin/disable — write the disabled flag so future wrapper invocations
/// enter bypass mode. Does NOT kill the running gateway.
async fn post_admin_disable() -> Json<EnabledResp> {
    let flag = disabled_flag_path();
    if let Some(parent) = flag.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::File::create(&flag);
    eprintln!("[admin] bleep disabled (flag: {})", flag.display());
    Json(EnabledResp { enabled: false })
}

/// POST /admin/enable — remove the disabled flag so the wrapper resumes proxying.
async fn post_admin_enable() -> Json<EnabledResp> {
    let flag = disabled_flag_path();
    let _ = std::fs::remove_file(&flag);
    eprintln!("[admin] bleep enabled (flag removed)");
    Json(EnabledResp { enabled: true })
}

#[derive(Deserialize)]
struct PerfQuery {
    reset: Option<u8>,
}

/// GET /perf — JSON snapshot of all gateway hot-path timing spans.
/// `?reset=1` zeroes counters after snapshotting (use to bench a fresh run).
async fn get_perf(Query(q): Query<PerfQuery>) -> Json<Vec<crate::perf::SpanReport>> {
    let snap = crate::perf::snapshot();
    if q.reset.unwrap_or(0) == 1 {
        crate::perf::reset();
    }
    Json(snap)
}

fn router() -> Router {
    // CORS: the listener is bound to 127.0.0.1 only, so any local origin is
    // implicitly trusted. The dashboard webview's origin shifts depending on
    // how Tauri loads the UI:
    //   - production / `frontendDist`  → `tauri://localhost`
    //   - debug + `devUrl`             → `http://localhost:1420` (the run-dev
    //                                     ui dev server, see run-dev.sh)
    // Permissive is the simplest correct policy for a loopback-only server.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health))
        .route("/stats", get(get_summary))
        .route("/stats/categories", get(get_categories))
        .route("/stats/rules", get(get_rules))
        .route("/rules/count", get(get_rules_count))
        .route("/redactions", get(get_redactions))
        .route("/stats/reset", post(post_stats_reset))
        .route("/perf", get(get_perf))
        .route("/perf/reset", post(post_perf_reset))
        .route("/dictionary/reset", post(post_dictionary_reset))
        .route("/admin/enabled", get(get_admin_enabled))
        .route("/admin/disable", post(post_admin_disable))
        .route("/admin/enable",  post(post_admin_enable))
        .fallback(not_found)
        .layer(cors)
}

/// Spawn the stats HTTP server on the first available port in the configured
/// range (prod: 9290..=9299, dev: 9490..=9499). Returns immediately; the
/// server runs in a tokio task. The bound port is written to the configured
/// port-file path (prod: /tmp/bleep-stats.port, dev: /tmp/bleep-stats-dev.port).
pub fn start() {
    tokio::spawn(async move {
        let range = crate::devmode::stats_port_range();
        let (start, end) = (*range.start(), *range.end());
        let listener = match bind_first_available().await {
            Some(l) => l,
            None => {
                eprintln!("[stats_server] no available port in {start}-{end} — server disabled");
                return;
            }
        };
        let port = match listener.local_addr() {
            Ok(a) => a.port(),
            Err(e) => {
                eprintln!("[stats_server] local_addr failed: {e}");
                return;
            }
        };
        if let Err(e) = std::fs::write(crate::devmode::stats_port_file(), port.to_string()) {
            eprintln!("[stats_server] failed to write port file: {e}");
        }
        println!("[stats_server] listening on http://127.0.0.1:{port}");

        // start the perf-dump background task (writes /tmp/bleep-perf.{json,jsonl})
        crate::perf::start_dump_task();

        if let Err(e) = axum::serve(listener, router()).await {
            eprintln!("[stats_server] serve error: {e}");
        }
    });
}

async fn bind_first_available() -> Option<TcpListener> {
    for port in crate::devmode::stats_port_range() {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)).await {
            return Some(l);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stats_returns_json() {
        let app = router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // shape check — fields exist even when DB is empty/uninitialized
        assert!(v.get("total").is_some());
        assert!(v.get("today").is_some());
        assert!(v.get("last_7d").is_some());
        assert!(v.get("last_30d").is_some());
    }

    #[tokio::test]
    async fn rules_default_limit() {
        let app = router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/stats/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cors_allow_origin_present() {
        // Tauri can load the webview from tauri://localhost (prod) or
        // http://localhost:1420 (dev with devUrl). Either way, fetches to the
        // stats server are cross-origin from the browser's POV. Pin that the
        // ACAO header is set so a refactor can't silently re-introduce the
        // "Origin … is not allowed by Access-Control-Allow-Origin" failure.
        let app = router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .header("Origin", "http://localhost:1420")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .expect("missing Access-Control-Allow-Origin header");
        assert_eq!(acao, "*");
    }

    #[tokio::test]
    async fn unknown_route_404() {
        let app = router();
        let resp = app
            .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
