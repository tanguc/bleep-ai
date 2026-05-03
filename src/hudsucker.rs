use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
    *,
};
use std::{io::Read, net::SocketAddr, path::Path, sync::Arc};
use tracing::*;

use crate::content_router;
use crate::content_router::audit;
use crate::event_bus;
use crate::event_bus::{ProxyEvent, RedactedEntry};
use crate::request_logger;

/// convert raw bytes to a loggable serde value
/// - gzip: decompress first
/// - valid json: parse into structured value (avoids escaped quotes/newlines)
/// - valid utf-8 text: store as string
/// - binary: placeholder with byte count
fn body_to_loggable(data: &[u8]) -> serde_json::Value {
    if data.is_empty() {
        return serde_json::Value::Null;
    }

    // gzip: magic bytes 1f 8b
    let text = if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = String::new();
        match decoder.read_to_string(&mut decompressed) {
            Ok(_) => decompressed,
            Err(_) => {
                return serde_json::json!(format!("<gzip decode failed, {} bytes>", data.len()));
            }
        }
    } else if let Ok(s) = std::str::from_utf8(data) {
        s.to_string()
    } else {
        return serde_json::json!(format!("<binary {} bytes>", data.len()));
    };

    // if the text is valid json, embed it as structured data
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
        return parsed;
    }

    // plain text (SSE streams, version strings, etc.)
    serde_json::Value::String(text)
}

/// returns true if request carries AWS SigV4 signature over the body
///
/// modifying the body of a signed request invalidates the signature.
/// skip replacement entirely and forward unchanged (PROXY-INTEGRATION.md §9).
fn is_signed_request(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("AWS4-HMAC-SHA256 Credential="))
        .unwrap_or(false)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");

    info!("shutting down...");
}

#[derive(Clone)]
struct LogHandler {
    /// path for JSONL audit log output
    log_file: Arc<String>,
    /// minimum confidence level: "low" | "medium" | "high"
    min_confidence: Arc<String>,
}

impl LogHandler {
    /// write audit entries for redactions that meet the min_confidence threshold
    fn write_audit(
        &self,
        request_id: &str,
        content_type: &str,
        redactions: &[crate::replacement::Redaction],
    ) {
        if redactions.is_empty() {
            return;
        }
        let entries = audit::make_audit_entries(request_id, content_type, redactions);
        let path = Path::new(self.log_file.as_str());
        if let Err(e) = audit::write_audit_entries(&entries, path) {
            warn!("[bleep] audit log write failed: {e}");
        }
    }

    /// build RedactedEntry vec from redactions for the event bus (fake values only)
    fn to_redacted_entries(redactions: &[crate::replacement::Redaction]) -> Vec<RedactedEntry> {
        redactions
            .iter()
            .map(|r| RedactedEntry {
                rule_id: r.rule_id.clone(),
                category: r.category.clone(),
                subcategory: r.subcategory.clone(),
                severity: r.severity.clone(),
                fake_value: r.fake.clone(),
            })
            .collect()
    }
}

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        // rewrite relative URIs to absolute so hyper can forward them
        if let Some(host) = req.uri().host().map(std::borrow::ToOwned::to_owned) {
            let path_and_query = req
                .uri()
                .path_and_query()
                .map_or("/", |pq| pq.as_str())
                .to_owned();
            *req.uri_mut() = format!("https://{host}{path_and_query}")
                .parse()
                .expect("failed to parse rewritten URI");
        }

        // signed request bypass: AWS SigV4 body modification invalidates signature
        if is_signed_request(req.headers()) {
            warn!(
                "[bleep] skipping replacement: AWS SigV4 signed request (rule: signed-request-bypass)"
            );
            return req.into();
        }

        // drain body
        let (mut parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        // extract content-type and content-encoding for routing
        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_encoding = parts
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let request_id = uuid::Uuid::new_v4().to_string();
        let content_type_str = content_type.as_deref().unwrap_or("");

        // call content router — handles all content types, compression, detection, replacement
        let (replaced_bytes, redactions) = content_router::process_body(
            content_type.as_deref(),
            content_encoding.as_deref(),
            bytes.clone(),
        );

        // log original body (before replacement for debugging)
        request_logger::log(&serde_json::json!({
            "type": "request",
            "ts": chrono::Utc::now().to_rfc3339(),
            "method": parts.method.as_str(),
            "uri": parts.uri.to_string(),
            "body": body_to_loggable(&bytes),
            "redactions": redactions.len(),
        }));

        if !redactions.is_empty() {
            // update Content-Length (only if header was present — never add for chunked)
            content_router::update_content_length(&mut parts.headers, replaced_bytes.len(), true);

            // write JSONL audit entries (original values stay on disk only)
            self.write_audit(&request_id, content_type_str, &redactions);

            // record metadata-only rows in the stats DB (originals never written here)
            crate::stats::record_redactions(
                crate::stats::Direction::Request,
                &request_id,
                &redactions,
            );

            // emit to event bus (fake values only — originals never on bus)
            let redacted_entries = Self::to_redacted_entries(&redactions);
            event_bus::emit(ProxyEvent::Request {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                redacted: redacted_entries,
            });
        } else {
            event_bus::emit(ProxyEvent::Request {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                redacted: vec![],
            });
        }

        let req = Request::from_parts(parts, Body::from(http_body_util::Full::new(replaced_bytes)));
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_encoding = parts
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let request_id = uuid::Uuid::new_v4().to_string();
        let content_type_str = content_type.as_deref().unwrap_or("");

        // SSE and non-SSE both go through process_body — sse_process_full handles per-frame
        // within the buffered body (hudsucker buffers full response before returning)
        let (replaced_bytes, redactions) = content_router::process_body(
            content_type.as_deref(),
            content_encoding.as_deref(),
            bytes.clone(),
        );

        request_logger::log(&serde_json::json!({
            "type": "response",
            "ts": chrono::Utc::now().to_rfc3339(),
            "status": parts.status.as_u16(),
            "body": body_to_loggable(&bytes),
            "redactions": redactions.len(),
        }));

        if !redactions.is_empty() {
            content_router::update_content_length(&mut parts.headers, replaced_bytes.len(), true);

            self.write_audit(&request_id, content_type_str, &redactions);

            crate::stats::record_redactions(
                crate::stats::Direction::Response,
                &request_id,
                &redactions,
            );

            let redacted_entries = Self::to_redacted_entries(&redactions);
            event_bus::emit(ProxyEvent::Response {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                uri: String::new(),
                status: parts.status.as_u16(),
            });
            // log redacted entries separately — Response event doesn't carry them
            for entry in redacted_entries {
                debug!(
                    "[bleep] response redaction: rule={} fake={}",
                    entry.rule_id, entry.fake_value
                );
            }
        } else {
            event_bus::emit(ProxyEvent::Response {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                uri: String::new(),
                status: parts.status.as_u16(),
            });
        }

        Response::from_parts(parts, Body::from(http_body_util::Full::new(replaced_bytes)))
    }
}

impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        info!("ws: {:?}", msg);
        Some(msg)
    }
}

pub async fn run_hudsucker(port: u16, log_file: String, min_confidence: String) {
    // force pattern compilation at startup, not on first request
    let rule_count = crate::patterns::get_normalized_rules().len();
    let _combined = crate::patterns::get_combined();
    let _rules = crate::patterns::get_rules();
    println!("compiled {rule_count} detection rules");

    request_logger::init();
    event_bus::init();
    event_bus::start_tcp_server();

    // initialize the redaction history DB (best-effort — failures are logged, proxy keeps running)
    let stats_path = crate::stats::default_path();
    if let Err(e) = crate::stats::init(&stats_path) {
        eprintln!("[stats] init failed for {}: {e}", stats_path.display());
    } else {
        println!("[stats] redaction history DB at {}", stats_path.display());
    }

    println!("starting hudsucker proxy on :{port}");

    let key_pair = KeyPair::from_pem(include_str!("key.pem")).expect("failed to parse private key");
    let issuer = Issuer::from_ca_cert_pem(include_str!("cert.pem"), key_pair)
        .expect("failed to parse CA cert");
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    let handler = LogHandler {
        log_file: Arc::new(log_file),
        min_confidence: Arc::new(min_confidence),
    };

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], port)))
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("failed to create proxy");

    println!("Proxy running. Press Ctrl+C to stop.");
    if let Err(e) = proxy.start().await {
        error!("{}", e);
    }
}
