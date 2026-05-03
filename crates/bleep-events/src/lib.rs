//! Wire-event types for the bleep proxy.
//!
//! This crate is the single source of truth for the JSON-on-the-wire
//! contract between the gateway (producer), the TUI (consumer), and the
//! menu-bar GUI (consumer). All three previously duplicated these types
//! and silently drifted — `fake_value` got dropped in the GUI, for
//! example. Anyone who needs the shape now imports it from here.
//!
//! Wire format: newline-delimited JSON over TCP, with `#[serde(tag = "type")]`
//! discrimination. Each line is one ProxyEvent.

use serde::{Deserialize, Serialize};

/// One redaction the proxy applied to a body.
///
/// Security note: `fake_value` is the substituted value (safe to display
/// or log). The original matched bytes are NEVER on this struct — they
/// stay only in the on-disk JSONL audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedEntry {
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub fake_value: String,
}

/// One event on the proxy event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
                fake_value: "AKIAxxx".into(),
            }],
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""type":"Request""#));
        assert!(s.contains(r#""fake_value":"AKIAxxx""#));
        // round-trip
        let back: ProxyEvent = serde_json::from_str(&s).unwrap();
        match back {
            ProxyEvent::Request { redacted, .. } => {
                assert_eq!(redacted[0].fake_value, "AKIAxxx");
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
