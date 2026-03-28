// content_router: dispatches HTTP bodies to format-specific handlers
// wires detection + replacement to HTTP body handling
// only module that knows about Content-Type, Content-Encoding, and HTTP body structure

mod json;
mod plain;
mod urlencoded;

pub mod audit;
pub mod headers;
pub mod sse;

#[cfg(test)]
mod tests;

use bytes::Bytes;
use flate2::read::{DeflateDecoder, GzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use std::io::{Read, Write};
use tracing::warn;

use crate::replacement::Redaction;

/// errors produced by the content router
#[derive(Debug)]
pub enum RouterError {
    DecompressionFailed(String),
    HandlerFailed(String),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::DecompressionFailed(msg) => write!(f, "decompression failed: {msg}"),
            RouterError::HandlerFailed(msg) => write!(f, "handler failed: {msg}"),
        }
    }
}

/// pluggable handler trait — implement this to add new content type handlers
pub trait ContentHandler: Send + Sync {
    fn process(&self, body: Bytes) -> Result<(Bytes, Vec<Redaction>), RouterError>;
}

/// main entry point — dispatches body to the appropriate handler based on content type
///
/// handles decompression (gzip/deflate) before routing and recompression after replacement.
/// on any processing error, returns original body unchanged (INV-04 fallback).
///
/// # arguments
/// - `content_type`: value of Content-Type header (e.g. "application/json")
/// - `content_encoding`: value of Content-Encoding header (e.g. "gzip")
/// - `body`: raw body bytes as received
///
/// # returns
/// `(processed_body, redactions)` — if no changes, body == input and redactions is empty
pub fn process_body(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    body: Bytes,
) -> (Bytes, Vec<Redaction>) {
    let encoding = content_encoding.unwrap_or("").to_ascii_lowercase();

    // step 1: decompress if needed (INV-06)
    let (decompressed, was_compressed) = match decompress(&body, &encoding) {
        Ok(result) => result,
        Err(e) => {
            warn!("[bleep] {e}, passing through");
            return (body, vec![]);
        }
    };

    // step 2: route to handler by content type
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    let handler_result = dispatch(&ct, decompressed.clone());

    let (replaced, redactions) = match handler_result {
        Ok(pair) => pair,
        Err(e) => {
            warn!("[bleep] INV-04: processing error: {e}, forwarding original");
            return (body, vec![]);
        }
    };

    // step 3: if body was compressed, recompress the replaced bytes
    if was_compressed {
        match recompress(&replaced, &encoding) {
            Ok(recompressed) => (Bytes::from(recompressed), redactions),
            Err(e) => {
                warn!(
                    "[bleep] recompression failed after replacement for {encoding}: {e}, forwarding decompressed body"
                );
                // return decompressed replaced bytes (replacement succeeded, just recompression failed)
                (replaced, redactions)
            }
        }
    } else {
        (replaced, redactions)
    }
}

/// update Content-Length header after body modification (INV-03)
///
/// only updates if had_replacements is true and the header already exists.
/// never adds Content-Length to chunked responses.
pub fn update_content_length(
    headers: &mut http::HeaderMap,
    new_len: usize,
    had_replacements: bool,
) {
    if !had_replacements {
        return;
    }
    if let Some(cl) = headers.get_mut(http::header::CONTENT_LENGTH) {
        if let Ok(val) = http::HeaderValue::from_str(&new_len.to_string()) {
            *cl = val;
        }
    }
}

/// decompress body based on Content-Encoding value
/// returns (decompressed_bytes, was_actually_compressed)
fn decompress(body: &Bytes, encoding: &str) -> Result<(Bytes, bool), RouterError> {
    if encoding.contains("gzip") {
        let mut decoder = GzDecoder::new(body.as_ref());
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|e| RouterError::DecompressionFailed(format!("[bleep] decompression failed for Content-Encoding gzip: {e}, passing through")))?;
        Ok((Bytes::from(out), true))
    } else if encoding.contains("deflate") {
        let mut decoder = DeflateDecoder::new(body.as_ref());
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|e| RouterError::DecompressionFailed(format!("[bleep] decompression failed for Content-Encoding deflate: {e}, passing through")))?;
        Ok((Bytes::from(out), true))
    } else if encoding.contains("br") {
        // brotli not supported in v1.0 — pass through
        warn!("[bleep] unsupported Content-Encoding: br, passing through");
        // return Err so caller passes through original
        Err(RouterError::DecompressionFailed(
            "[bleep] unsupported Content-Encoding: br, passing through".into(),
        ))
    } else {
        // no compression
        Ok((body.clone(), false))
    }
}

/// recompress bytes using the original encoding
fn recompress(data: &[u8], encoding: &str) -> Result<Vec<u8>, std::io::Error> {
    if encoding.contains("gzip") {
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)?;
        encoder.finish()
    } else if encoding.contains("deflate") {
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)?;
        encoder.finish()
    } else {
        Ok(data.to_vec())
    }
}

/// dispatch decompressed body to format-specific handler
fn dispatch(ct: &str, body: Bytes) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    if ct.starts_with("application/json") {
        json::handle(body)
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        urlencoded::handle(body)
    } else if ct.starts_with("multipart/form-data") {
        // extract boundary parameter
        if let Some(boundary) = extract_boundary(ct) {
            crate::content_router::multipart_dispatch(body, &boundary)
        } else {
            warn!("[bleep] multipart/form-data missing boundary parameter, falling back to plain-text");
            plain::handle(body)
        }
    } else if ct.starts_with("text/event-stream") {
        let (out, redactions) = sse::sse_process_full(body);
        Ok((out, redactions))
    } else if is_binary_content_type(ct) {
        // binary types: pass through unmodified (INP-09)
        Ok((body, vec![]))
    } else {
        // unknown or absent: treat as plain text per spec
        plain::handle(body)
    }
}

/// extract boundary parameter from multipart/form-data content type string
fn extract_boundary(ct: &str) -> Option<String> {
    for part in ct.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("boundary=") {
            return Some(val.trim_matches('"').to_string());
        }
    }
    None
}

/// returns true if content type is a binary type that should pass through
fn is_binary_content_type(ct: &str) -> bool {
    ct.starts_with("image/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct == "application/octet-stream"
        || ct.starts_with("application/octet-stream")
}

/// dispatch multipart body — called from dispatch() after boundary extraction
/// separated to allow forward reference from dispatch
fn multipart_dispatch(body: Bytes, boundary: &str) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    use crate::content_router::multipart;
    multipart::handle(body, boundary)
}

// multipart module declared here so it's available for forward reference in dispatch
mod multipart;
