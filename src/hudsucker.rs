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
use serde::Serialize;
use std::{io::Read, net::SocketAddr, sync::Arc};
use tracing::*;

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

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");

    info!("shutting down...");
}

#[derive(Clone)]
struct LogHandler {
    log_file: Arc<String>,
    min_confidence: Arc<String>,
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

        // drain body
        let (mut parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        // TODO(phase-5): wire detection::scan() + replacement::apply() here
        // for now: passthrough — body is forwarded unchanged
        let replaced_bytes = bytes.clone();

        // log original body
        request_logger::log(&serde_json::json!({
            "type": "request",
            "ts": chrono::Utc::now().to_rfc3339(),
            "method": parts.method.as_str(),
            "uri": parts.uri.to_string(),
            "body": body_to_loggable(&bytes),
        }));

        event_bus::emit(ProxyEvent::Request {
            id: uuid::Uuid::new_v4().to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            redacted: vec![],
        });

        // fix content-length if present (body unchanged so length is same, but keep consistent)
        if parts.headers.contains_key(hyper::header::CONTENT_LENGTH) {
            parts.headers.insert(
                hyper::header::CONTENT_LENGTH,
                hyper::header::HeaderValue::from(replaced_bytes.len()),
            );
        }

        let req = Request::from_parts(parts, Body::from(http_body_util::Full::new(replaced_bytes)));
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        request_logger::log(&serde_json::json!({
            "type": "response",
            "ts": chrono::Utc::now().to_rfc3339(),
            "status": parts.status.as_u16(),
            "body": body_to_loggable(&bytes),
        }));

        event_bus::emit(ProxyEvent::Response {
            id: uuid::Uuid::new_v4().to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
            uri: String::new(),
            status: parts.status.as_u16(),
        });

        Response::from_parts(parts, Body::from(http_body_util::Full::new(bytes)))
    }
}

impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        info!("ws: {:?}", msg);
        Some(msg)
    }
}

pub async fn run_hudsucker(port: u16, log_file: String, min_confidence: String) {
    request_logger::init();
    event_bus::init();
    event_bus::start_tcp_server();
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
        .with_websocket_handler(handler.clone())
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("failed to create proxy");

    if let Err(e) = proxy.start().await {
        error!("{}", e);
    }
}
