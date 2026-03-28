use std::{
    fmt::Debug,
    str::{self, FromStr},
    sync::Arc,
    usize,
};

use crate::{logging::log_entry, types};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
    http::Request,
    http::Response,
};
use bytes::Bytes;
use hyper::Method;
use reqwest::Proxy;
use std::sync::Mutex;
use tracing::{debug, info};

pub fn is_streaming_request(body: &Vec<u8>) -> bool {
    let serde_json_body = serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|e| {
            debug!("Failed to parse request body as JSON: {}", e);
            e
        })
        .ok();
    let _pretty_json = serde_json::to_string_pretty(&serde_json_body).unwrap();
    debug!("Request body as JSON: {:#?}", serde_json_body);

    if serde_json_body.unwrap().get("stream").is_some() {
        debug!("Request body has 'stream' field, treating as streaming request");
        return true;
    }

    debug!("Request body does not have 'stream' field, treating as non-streaming request");
    return false;
}

pub fn debug_pretty_print(data: &[u8]) {
    let serde_json_data = serde_json::from_slice::<serde_json::Value>(data)
        .map_err(|e| {
            debug!("Failed to parse data as JSON: {}", e);
            e
        })
        .ok();

    if let Some(serde_json_data) = &serde_json_data {
        let pretty_json = serde_json::to_string_pretty(&serde_json_data).unwrap();
        debug!("{}", pretty_json);
    } else {
        let str_data = str::from_utf8(data)
            .map_err(|e| {
                debug!("Failed to parse data as UTF-8 string: {}", e);
                e
            })
            .ok();
        debug!("Data is not valid JSON, printing as bytes: {:#?}", str_data);
    }
}

pub struct ProxyReqBuf {
    chunks: Vec<Bytes>,
}

impl ProxyReqBuf {
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    pub fn append(&mut self, chunk: &Bytes) {
        debug!(
            "Appending chunk of size {} bytes to ProxyReqBuf",
            chunk.len()
        );
        self.chunks.push(chunk.clone());
    }

    pub fn to_bytes(&self) -> Bytes {
        let total_len: usize = self.chunks.iter().map(|c| c.len()).sum();
        let mut buf = Vec::with_capacity(total_len);
        for chunk in &self.chunks {
            buf.extend_from_slice(chunk);
        }
        Bytes::from(buf)
    }

    pub fn to_string(&self) -> String {
        let bytes = self.to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }
}

/// forwards incoming request to anthropic API and returns the response
/// handles both streaming (SSE) and non-streaming modes
pub async fn proxy_handler(
    Path(path): Path<String>,
    State(state): State<types::AppState>,
    req: Request<Body>,
) -> Response<Body> {
    let start_time = std::time::Instant::now();
    debug!("Received request path: {}", path);
    debug!("Request whole : {:#?}", &req);

    let (parts, body) = req.into_parts();
    let header: HeaderMap = parts
        .headers
        .iter()
        .filter(|(header, _)| header.as_str() != "host")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let method = Method::from_str(parts.method.as_str()).unwrap();
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();

    let r = state
        .client
        .request(method, format!("https://api.anthropic.com/{path}"))
        .headers(header)
        .body(body_bytes)
        .send()
        .await
        .unwrap();
    debug!("Received response: {:#?}", r);

    let r_headers: reqwest::header::HeaderMap = r
        .headers()
        .iter()
        .filter(|(header, _)| header.as_str() != "host")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let r_status = r.status();

    let req_buf = Arc::new(Mutex::new(ProxyReqBuf::new()));
    let req_buf_inner = req_buf.clone();
    let req_buf_done = req_buf.clone();

    let start_time_buf = std::time::Instant::now();
    let axum_body_stream = {
        use futures_util::StreamExt;
        let chunks_stream = r.bytes_stream().map(move |chunk| match chunk {
            Ok(chunk) => {
                req_buf_inner.lock().unwrap().append(&chunk);
                Ok(chunk)
            }
            Err(err) => {
                debug!("Error receiving chunk: {:#?}", err);
                Err(err)
            }
        });

        // fires after the last real chunk has been consumed
        let on_complete = futures_util::stream::once(async move {
            debug!(
                "Stream complete ({} ms). Full response body: {}",
                start_time_buf.elapsed().as_millis(),
                req_buf_done.lock().unwrap().to_string()
            );
            Ok(Bytes::new()) // empty chunk, harmless
        });

        Body::from_stream(chunks_stream.chain(on_complete))
    };

    let mut downstream_r_builder = Response::builder();
    for (k, v) in &r_headers {
        downstream_r_builder = downstream_r_builder.header(k, v);
    }

    let downstream_r = downstream_r_builder
        .status(r_status)
        .body(axum_body_stream)
        .unwrap();

    debug!(
        "Request processing took {} ms",
        start_time.elapsed().as_millis()
    );

    downstream_r

    // TODO: extract request body
    // TODO: forward to https://api.anthropic.com/v1/messages
    // TODO: set x-api-key and anthropic-version headers
    // TODO: if stream: true, pipe SSE events back to client
    // TODO: if stream: false, return full JSON response
    // TODO: call logging::log_entry() with captured data
}
