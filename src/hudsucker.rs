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

/// IPv4-only DNS resolver wrapper around hyper_util's GaiResolver.
///
/// Drops AAAA results so the connector only ever sees v4 destinations and
/// creates v4 sockets. See `build_upstream_connector` for why.
#[derive(Clone)]
struct Ipv4OnlyResolver(hyper_util::client::legacy::connect::dns::GaiResolver);

impl tower::Service<hyper_util::client::legacy::connect::dns::Name> for Ipv4OnlyResolver {
    type Response = std::vec::IntoIter<std::net::SocketAddr>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        tower::Service::poll_ready(&mut self.0, cx)
    }

    fn call(
        &mut self,
        name: hyper_util::client::legacy::connect::dns::Name,
    ) -> Self::Future {
        let fut = tower::Service::call(&mut self.0, name);
        Box::pin(async move {
            let addrs = fut.await?;
            Ok(addrs.filter(|a| a.is_ipv4()).collect::<Vec<_>>().into_iter())
        })
    }
}

/// Build the upstream HTTPS connector hudsucker uses to dial origin servers.
///
/// Forces IPv4-only resolution via a custom DNS wrapper. macOS VPN clients
/// (Surfshark in particular) routinely break the v6 default route on
/// connect/disconnect; the gateway would then resolve api.anthropic.com to a
/// v6 address and hang on a dead route until TCP timeout (~75s). Stripping
/// AAAA at the resolver layer means the connector only ever creates v4
/// sockets — Anthropic + all our upstreams have full v4 connectivity.
fn build_upstream_connector()
-> impl hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static {
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::connect::dns::GaiResolver;
    use std::time::Duration;

    let resolver = Ipv4OnlyResolver(GaiResolver::new());
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_happy_eyeballs_timeout(None);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(Some(Duration::from_secs(15)));

    let provider = hudsucker::rustls::crypto::aws_lc_rs::default_provider();
    use hyper_rustls::ConfigBuilderExt;
    let tls = hudsucker::rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("default rustls protocol versions")
        .with_webpki_roots()
        .with_no_client_auth();

    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}

/// Build the hyper Client with a short pool idle timeout so stale sockets
/// (e.g. left over after a VPN toggle / network change) get evicted within
/// 10s instead of the default 90s. Caps idle connections per host so the
/// pool can't accumulate dozens of dead sockets between requests.
fn build_upstream_client_builder() -> hyper_util::client::legacy::Builder {
    use hyper_util::rt::TokioExecutor;
    use std::time::Duration;

    let mut b = hyper_util::client::legacy::Client::builder(TokioExecutor::new());
    // hudsucker's default sets these too; keep parity.
    b.http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .pool_idle_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(8);
    b
}

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
    /// redactions applied to the in-flight request, consumed by the matching
    /// response so fakes are restored to originals before the body reaches the
    /// client. Per hudsucker: each request/response pair runs on the same
    /// handler instance, so this needs no external keying.
    pending_redactions: Vec<crate::replacement::Redaction>,
    /// request_id of the in-flight request, reused for response-side logging
    pending_request_id: Option<String>,
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
                original: r.original.clone(),
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
        let _g_total = crate::perf::span("hudsucker.request.total");
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
        let t_body = std::time::Instant::now();
        let bytes = body.collect().await.unwrap().to_bytes();
        crate::perf::record("hudsucker.request.body_collect", t_body.elapsed());

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
        let t_router = std::time::Instant::now();
        let (replaced_bytes, redactions) = content_router::process_body(
            content_type.as_deref(),
            content_encoding.as_deref(),
            bytes.clone(),
        );
        crate::perf::record("hudsucker.request.content_router", t_router.elapsed());

        // stash the request's redactions so the paired handle_response can
        // restore real values in the model's reply (which echoes the fakes
        // it saw). Same handler instance per request/response per hudsucker.
        self.pending_redactions = redactions.clone();
        self.pending_request_id = Some(request_id.clone());

        // persist every (fake, original) pair so future responses can still
        // restore fakes that leaked into files or that came from sessions
        // predating this gateway run.
        if !redactions.is_empty() {
            crate::dictionary::record_batch(&redactions);
        }

        // log original body (before replacement for debugging)
        let t_log = std::time::Instant::now();
        request_logger::log(&serde_json::json!({
            "type": "request",
            "ts": chrono::Utc::now().to_rfc3339(),
            "method": parts.method.as_str(),
            "uri": parts.uri.to_string(),
            "body": body_to_loggable(&bytes),
            "redactions": redactions.len(),
        }));
        crate::perf::record("hudsucker.request.audit_log", t_log.elapsed());

        if !redactions.is_empty() {
            // update Content-Length (only if header was present — never add for chunked)
            content_router::update_content_length(&mut parts.headers, replaced_bytes.len(), true);

            // write JSONL audit entries (original values stay on disk only)
            let t_audit = std::time::Instant::now();
            self.write_audit(&request_id, content_type_str, &redactions);
            crate::perf::record("hudsucker.request.write_audit", t_audit.elapsed());

            // record metadata-only rows in the stats DB (originals never written here)
            let t_db = std::time::Instant::now();
            crate::stats::record_redactions(
                crate::stats::Direction::Request,
                &request_id,
                &redactions,
            );
            crate::perf::record("hudsucker.request.stats_insert", t_db.elapsed());

            // emit to event bus (fake values only — originals never on bus)
            let t_emit = std::time::Instant::now();
            let redacted_entries = Self::to_redacted_entries(&redactions);
            event_bus::emit(ProxyEvent::Request {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                redacted: redacted_entries,
            });
            crate::perf::record("hudsucker.request.event_emit", t_emit.elapsed());
        } else {
            let t_emit = std::time::Instant::now();
            event_bus::emit(ProxyEvent::Request {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                redacted: vec![],
            });
            crate::perf::record("hudsucker.request.event_emit_empty", t_emit.elapsed());
        }

        // Disable upstream keep-alive. Hudsucker's hyper client otherwise
        // pools idle TLS connections per-host; under burst load (e.g. parallel
        // test traffic) those connections race the upstream's idle-timeout FIN
        // and surface as "connection closed before message completed" errors.
        // `Connection: close` makes each forward a fresh, single-shot
        // connection — costs one TLS handshake per request but eliminates
        // pool-staleness errors. Body integrity is preserved (handshake is
        // separate from body framing). Also strips Keep-Alive so we don't
        // send conflicting hop-by-hop headers.
        parts.headers.remove(http::header::CONNECTION);
        parts.headers.remove("keep-alive");
        parts.headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );

        // Ask the upstream to skip gzip so the response-side streaming
        // deanonymizer can operate on plaintext bytes (gzip can't be
        // decompressed incrementally without buffering, and buffering
        // defeats SSE streaming UX).
        //
        // Why `gzip;q=0` and not `identity`:
        //   - `identity` means "ONLY identity"; RFC 9110 lets the server
        //     reject with 406 Not Acceptable.
        //   - `gzip;q=0` means "anything except gzip" — softer, well-
        //     established convention in SSE proxy code (nginx `gzip off`,
        //     http-proxy-middleware, Sourcegraph Cody, etc.).
        //
        // NOTE: a non-compliant origin can still ignore this and send gzip.
        // If we ever see that with Anthropic we'd need a streaming gzip
        // decoder in StreamingDeanon — not implemented yet.
        parts.headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip;q=0"),
        );

        let req = Request::from_parts(parts, Body::from(http_body_util::Full::new(replaced_bytes)));
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let _g_total = crate::perf::span("hudsucker.response.total");
        let (mut parts, body) = res.into_parts();

        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // SSE responses (Anthropic v1/messages) are streamed: hudsucker holds
        // off forwarding to the client until we return, and body.collect() can
        // block for tens of seconds on a long reply. Buffering also defeats
        // the user's "live tokens" UX. For text/event-stream we wrap the body
        // in StreamingDeanon and return immediately — bytes get rewritten as
        // they flow through.
        let is_sse = content_type
            .as_deref()
            .map(|ct| ct.starts_with("text/event-stream"))
            .unwrap_or(false);
        if is_sse {
            let in_flight = std::mem::take(&mut self.pending_redactions);
            let request_id = self
                .pending_request_id
                .take()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let dict_pairs = crate::dictionary::snapshot_pairs();
            // we forced Accept-Encoding: identity on the way out, so strip
            // any lingering encoding/length headers from upstream metadata.
            parts.headers.remove(http::header::CONTENT_ENCODING);
            parts.headers.remove(http::header::CONTENT_LENGTH);

            let wrapped = crate::streaming_deanon::StreamingDeanon::new(
                body,
                &in_flight,
                &dict_pairs,
            );
            // hudsucker's Body only exposes from_stream, so convert our Body
            // impl into a Stream of Bytes (trailers are dropped — SSE doesn't
            // use them anyway).
            let stream = BodyExt::into_data_stream(wrapped);

            event_bus::emit(ProxyEvent::Response {
                id: request_id,
                ts: chrono::Utc::now().to_rfc3339(),
                uri: String::new(),
                status: parts.status.as_u16(),
            });
            return Response::from_parts(parts, Body::from_stream(stream));
        }

        let t_body = std::time::Instant::now();
        let bytes = body.collect().await.unwrap().to_bytes();
        crate::perf::record("hudsucker.response.body_collect", t_body.elapsed());

        let content_encoding = parts
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // restore originals: walk the response and swap fakes back to real
        // values using BOTH the redactions captured during handle_request AND
        // the persistent dictionary (covers fakes the model echoes from files
        // or prior-session conversation context). We never re-run the
        // anonymizer here — that would mint new fakes for PII the model
        // legitimately includes in its reply.
        let in_flight = std::mem::take(&mut self.pending_redactions);
        let request_id = self
            .pending_request_id
            .take()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let t_router = std::time::Instant::now();
        let restored_bytes = content_router::deanonymize_body_with_dictionary(
            bytes.clone(),
            content_encoding.as_deref(),
            &in_flight,
            &crate::dictionary::snapshot_pairs(),
        );
        crate::perf::record("hudsucker.response.content_router", t_router.elapsed());
        let redactions = in_flight;

        let t_log = std::time::Instant::now();
        request_logger::log(&serde_json::json!({
            "type": "response",
            "ts": chrono::Utc::now().to_rfc3339(),
            "status": parts.status.as_u16(),
            "body": body_to_loggable(&bytes),
            "deanonymized": redactions.len(),
        }));
        crate::perf::record("hudsucker.response.audit_log", t_log.elapsed());

        if restored_bytes.len() != bytes.len() {
            content_router::update_content_length(&mut parts.headers, restored_bytes.len(), true);
        }

        let t_emit = std::time::Instant::now();
        event_bus::emit(ProxyEvent::Response {
            id: request_id,
            ts: chrono::Utc::now().to_rfc3339(),
            uri: String::new(),
            status: parts.status.as_u16(),
        });
        crate::perf::record("hudsucker.response.event_emit", t_emit.elapsed());

        Response::from_parts(parts, Body::from(http_body_util::Full::new(restored_bytes)))
    }

    /// only MITM Anthropic traffic — everything else (MCP servers, package
    /// registries, 1Password, etc.) is tunneled raw without TLS interception.
    /// avoids the noisy NO_PROXY list and zero overhead for non-target traffic.
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        // for CONNECT, the URI is "host:port"; for absolute-form HTTP, it has a host()
        let host = req
            .uri()
            .host()
            .map(str::to_owned)
            .or_else(|| {
                req.uri()
                    .authority()
                    .map(|a| a.host().to_owned())
            })
            .unwrap_or_default();
        let should = host == "api.anthropic.com" || host.ends_with(".anthropic.com");
        if !should {
            debug!("[bleep] pass-through (no MITM): {host}");
        }
        should
    }
}

impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        info!("ws: {:?}", msg);
        Some(msg)
    }
}

#[cfg(unix)]
fn spawn_parent_watchdog() {
    // env var is set by the menu-bar app when spawning us as a child.
    // Outside that case (running standalone), we do nothing.
    let Ok(parent_pid_str) = std::env::var("BLEEP_PARENT_PID") else {
        return;
    };
    let Ok(expected_parent) = parent_pid_str.parse::<u32>() else {
        return;
    };
    println!("[parent-watchdog] watching parent pid {expected_parent}");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            tick.tick().await;
            // SAFETY: getppid is always safe to call.
            let current = unsafe { libc::getppid() } as u32;
            if current != expected_parent {
                eprintln!(
                    "[parent-watchdog] parent gone (was {expected_parent}, now {current}) — exiting"
                );
                std::process::exit(0);
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_parent_watchdog() {}

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

    // initialize the persistent fake↔original dictionary. This survives gateway
    // restarts so fakes that leaked into files / conversation history during
    // earlier sessions can still be round-tripped.
    let dict_path = crate::dictionary::default_path();
    if let Err(e) = crate::dictionary::init(&dict_path) {
        eprintln!("[dictionary] init failed for {}: {e}", dict_path.display());
    }

    // start the local HTTP stats server for the menu-bar dashboard
    crate::stats_server::start();

    // when run as a child of the menu-bar app (BLEEP_PARENT_PID set), exit
    // if the parent dies. macOS reparents orphans to launchd (PID 1), which
    // we detect and treat as a shutdown signal.
    spawn_parent_watchdog();

    println!("starting hudsucker proxy on :{port}");

    // per-install CA: generated into ~/.bleep/ca/ on first launch (see src/ca.rs).
    // never baked into the binary or the repo — the private key stays on-machine.
    let (cert_pem, key_pem) = crate::ca::ensure_ca().expect("failed to load/generate MITM CA");
    let key_pair = KeyPair::from_pem(&key_pem).expect("failed to parse CA private key");
    let issuer =
        Issuer::from_ca_cert_pem(&cert_pem, key_pair).expect("failed to parse CA cert");
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    let handler = LogHandler {
        log_file: Arc::new(log_file),
        min_confidence: Arc::new(min_confidence),
        pending_redactions: Vec::new(),
        pending_request_id: None,
    };

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], port)))
        .with_ca(ca)
        .with_http_connector(build_upstream_connector())
        .with_client(build_upstream_client_builder())
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("failed to create proxy");

    println!("Proxy running. Press Ctrl+C to stop.");
    if let Err(e) = proxy.start().await {
        error!("{:?}", e);
    }
}
