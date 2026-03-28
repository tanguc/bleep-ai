use serde::{Deserialize, Serialize};

/// shared state passed to all handlers via axum State extractor
#[derive(Clone)]
pub struct AppState {
    // TODO: api_key, reqwest::Client, log writer handle
    pub anthropic_api_key: String,

    pub client: reqwest::Client,

    pub log_file: String,
}

/// captures metadata + bodies for a single proxied request/response cycle
#[derive(Serialize, Deserialize)]
pub struct LogEntry {
    // TODO: id, timestamp, method, path, request_body, response_status, response_body, latency_ms
}
