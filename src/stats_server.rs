//! Local HTTP server that exposes redaction stats from the SQLite history DB.
//!
//! Bound to 127.0.0.1 only — never listens on a public interface. Routes:
//!   GET /health             -> { "status": "ok" }
//!   GET /stats              -> Summary { total, last_24h, last_7d, last_30d }
//!   GET /stats/categories   -> [ { category, subcategory, count }, ... ]
//!   GET /stats/rules?limit  -> [ { rule_id, count }, ... ]   (limit default: 20)
//!
//! Live updates are not served here — the menu-bar app subscribes to the
//! existing TCP event_bus (port discovered via /tmp/bleep-events.port).
//!
//! The bound port is written to /tmp/bleep-stats.port for the Tauri app to
//! discover. Mirrors the event_bus startup pattern.

use axum::{Json, Router, extract::Query, http::StatusCode, routing::get};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::stats;

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Deserialize)]
struct RulesQuery {
    limit: Option<usize>,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn get_summary() -> Json<stats::Summary> {
    Json(stats::summary())
}

async fn get_categories() -> Json<Vec<stats::CategoryCount>> {
    Json(stats::by_category())
}

async fn get_rules(Query(q): Query<RulesQuery>) -> Json<Vec<stats::RuleCount>> {
    let limit = q.limit.unwrap_or(20).clamp(1, 1000);
    Json(stats::top_rules(limit))
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/stats", get(get_summary))
        .route("/stats/categories", get(get_categories))
        .route("/stats/rules", get(get_rules))
        .fallback(not_found)
}

/// Spawn the stats HTTP server on the first available port in 9290..=9299.
/// Returns immediately; the server runs in a tokio task. The bound port is
/// also written to `/tmp/bleep-stats.port` for the menu-bar app to discover.
pub fn start() {
    tokio::spawn(async move {
        let listener = match bind_first_available().await {
            Some(l) => l,
            None => {
                eprintln!("[stats_server] no available port in 9290-9299 — server disabled");
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
        if let Err(e) = std::fs::write("/tmp/bleep-stats.port", port.to_string()) {
            eprintln!("[stats_server] failed to write port file: {e}");
        }
        println!("[stats_server] listening on http://127.0.0.1:{port}");

        if let Err(e) = axum::serve(listener, router()).await {
            eprintln!("[stats_server] serve error: {e}");
        }
    });
}

async fn bind_first_available() -> Option<TcpListener> {
    for port in 9290u16..=9299 {
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
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stats_returns_json() {
        let app = router();
        let resp = app
            .oneshot(Request::builder().uri("/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // shape check — fields exist even when DB is empty/uninitialized
        assert!(v.get("total").is_some());
        assert!(v.get("last_24h").is_some());
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
    async fn unknown_route_404() {
        let app = router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
