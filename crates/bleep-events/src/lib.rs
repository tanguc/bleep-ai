//! Wire-contract types for the bleep proxy.
//!
//! This crate is the single source of truth for every JSON shape that
//! crosses the gateway ↔ consumer boundary:
//!   - event bus (TCP, NDJSON): `ProxyEvent`, `RedactedEntry`
//!   - stats HTTP API (axum): `Summary`, `CategoryCount`, `RuleCount`
//!
//! Consumers (TUI, menu-bar GUI) used to maintain their own duplicates that
//! silently drifted (e.g. `fake_value` was dropped in the GUI for a while).
//! Now everyone imports from here, and `ts-rs` regenerates TS bindings under
//! `bindings/` on `cargo test --package bleep-events` so the JS dashboard
//! gets compile-time-checked types via the `@bleep-events/*` jsconfig alias.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One redaction the proxy applied to a body.
///
/// Security note: `fake_value` is the substituted value (safe to display
/// or log). The original matched bytes are NEVER on this struct — they
/// stay only in the on-disk JSONL audit log.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RedactedEntry {
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub original: String,
    pub fake_value: String,
}

/// One event on the proxy event bus.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(tag = "type")]
pub enum ProxyEvent {
    Request {
        id: String,
        ts: String,
        method: String,
        uri: String,
        redacted: Vec<RedactedEntry>,
    },
    Response {
        id: String,
        ts: String,
        uri: String,
        status: u16,
    },
}

// ── stats HTTP API contract ───────────────────────────────────────────────────
// Consumed by the menu-bar dashboard at GET /stats, /stats/categories,
// /stats/rules. The gateway's stats module re-exports these so its public
// API doesn't need to change when shapes evolve.

/// `GET /stats` — aggregated counts for the dashboard summary card.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Summary {
    // ts-rs would map u64→bigint, but JSON.parse returns number — the
    // realistic shape on the wire. Override per-field; counts here will
    // never approach 2^53.
    #[ts(type = "number")]
    pub total: u64,
    /// redactions since local midnight today — a calendar day, not a
    /// rolling 24h window (the rolling window bled yesterday's counts in).
    #[ts(type = "number")]
    pub today: u64,
    /// last 7 calendar days, inclusive of today (since local midnight, 6 days ago).
    #[ts(type = "number")]
    pub last_7d: u64,
    /// last 30 calendar days, inclusive of today (since local midnight, 29 days ago).
    #[ts(type = "number")]
    pub last_30d: u64,
}

/// `GET /stats/categories` — one row of the (category, subcategory) breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CategoryCount {
    pub category: String,
    pub subcategory: String,
    #[ts(type = "number")]
    pub count: u64,
}

/// `GET /stats/rules?limit=N` — one row of the rule-level breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RuleCount {
    pub rule_id: String,
    #[ts(type = "number")]
    pub count: u64,
}

/// `GET /redactions?…` — one row of the full per-redaction drill-down.
/// Carries the secret half (`original`, `fake_value`) so this endpoint must
/// remain loopback-only (see `src/stats/mod.rs` doc comment).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RedactedRow {
    /// monotonically increasing row id from the redactions table — also serves as the pagination cursor
    #[ts(type = "number")]
    pub id: i64,
    /// unix epoch seconds
    #[ts(type = "number")]
    pub ts: i64,
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    /// "request" | "response"
    pub direction: String,
    pub request_id: String,
    pub original: String,
    pub fake_value: String,
}

/// `GET /redactions` envelope — caller gets a page and the cursor to continue.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RedactedPage {
    pub rows: Vec<RedactedRow>,
    /// pass back as `?cursor=` to fetch the next page. `null` when exhausted.
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire format must remain stable: `{"type":"Request",...}` shape.
    /// If someone changes the tag config or field names, this catches it.
    #[test]
    fn request_serializes_with_tag_field() {
        let ev = ProxyEvent::Request {
            id: "req-1".into(),
            ts: "2026-01-01T00:00:00Z".into(),
            method: "POST".into(),
            uri: "https://api.example.com".into(),
            redacted: vec![RedactedEntry {
                rule_id: "gl.aws".into(),
                category: "secret".into(),
                subcategory: "aws".into(),
                severity: "high".into(),
                original: "AKIAITSORIGINALEVALUE".into(),
                fake_value: "AKIAxxx".into(),
            }],
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""type":"Request""#));
        assert!(s.contains(r#""fake_value":"AKIAxxx""#));
        assert!(s.contains(r#""original":"AKIAITSORIGINALEVALUE""#));
        // round-trip
        let back: ProxyEvent = serde_json::from_str(&s).unwrap();
        match back {
            ProxyEvent::Request { redacted, .. } => {
                assert_eq!(redacted[0].fake_value, "AKIAxxx");
                assert_eq!(redacted[0].original, "AKIAITSORIGINALEVALUE");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_serializes_with_tag_field() {
        let ev = ProxyEvent::Response {
            id: "req-1".into(),
            ts: "2026-01-01T00:00:00Z".into(),
            uri: "".into(),
            status: 200,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""type":"Response""#));
        assert!(s.contains(r#""status":200"#));
    }
}
