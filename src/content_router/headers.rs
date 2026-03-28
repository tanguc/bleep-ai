// http header scanner — Authorization, X-Api-Key, X-Auth-Token, X-Secret, name-pattern headers
// implements INP-06, INP-07

use bytes::Bytes;
use crate::replacement::Redaction;

/// headers that are always excluded from scanning (standard informational headers)
const EXCLUSIONS: &[&str] = &[
    "content-type",
    "content-length",
    "user-agent",
    "accept",
    "host",
    "accept-encoding",
    "cache-control",
    "accept-language",
    "connection",
    "transfer-encoding",
    "content-encoding",
];

/// scan sensitive HTTP headers and replace any detected secrets
///
/// modifies header values in-place.
/// returns all redactions for audit logging.
/// does not touch Content-Length (header scan never changes body).
pub fn scan_headers(headers: &mut http::HeaderMap) -> Vec<Redaction> {
    let mut all_redactions: Vec<Redaction> = Vec::new();

    // collect header names to process (cannot borrow headers mutably while iterating)
    let names: Vec<http::HeaderName> = headers
        .keys()
        .filter(|name| should_scan_header(name.as_str()))
        .cloned()
        .collect();

    for name in names {
        let name_str = name.as_str().to_ascii_lowercase();

        // get current value bytes
        let value_bytes = match headers.get(&name) {
            Some(v) => v.as_bytes().to_vec(),
            None => continue,
        };

        let redactions = if name_str == "authorization" {
            scan_authorization_header(&mut all_redactions, headers, &name, &value_bytes)
        } else {
            scan_raw_header_value(headers, &name, &value_bytes)
        };

        all_redactions.extend(redactions);
    }

    all_redactions
}

/// returns true if this header name should be scanned
fn should_scan_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // check exclusion list first
    if EXCLUSIONS.contains(&lower.as_str()) {
        return false;
    }
    // always-included headers
    if matches!(
        lower.as_str(),
        "authorization" | "x-api-key" | "x-auth-token" | "x-secret"
    ) {
        return true;
    }
    // name-pattern: contains key, secret, token, or password
    lower.contains("key")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("password")
}

/// handle Authorization header with Bearer/Basic special cases
fn scan_authorization_header(
    _redactions: &mut Vec<Redaction>,
    headers: &mut http::HeaderMap,
    name: &http::HeaderName,
    value_bytes: &[u8],
) -> Vec<Redaction> {
    let value_str = String::from_utf8_lossy(value_bytes);

    if let Some(token) = value_str.strip_prefix("Bearer ") {
        // scan only the token portion
        let token_bytes = Bytes::copy_from_slice(token.as_bytes());
        let matches = crate::detection::scan_field(&token_bytes);
        if matches.is_empty() {
            return vec![];
        }
        let (replaced_token, redactions) = crate::replacement::apply(token_bytes, matches);
        let new_value = format!("Bearer {}", String::from_utf8_lossy(&replaced_token));
        if let Ok(hv) = http::HeaderValue::from_str(&new_value) {
            headers.insert(name.clone(), hv);
        }
        redactions
    } else if let Some(encoded) = value_str.strip_prefix("Basic ") {
        // base64-decode, scan decoded string, re-encode after replacement
        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            Ok(d) => d,
            Err(_) => {
                // not valid base64 — scan raw value
                return scan_raw_header_value(headers, name, value_bytes);
            }
        };
        let decoded_bytes = Bytes::from(decoded);
        let matches = crate::detection::scan_field(&decoded_bytes);
        if matches.is_empty() {
            return vec![];
        }
        let (replaced, redactions) = crate::replacement::apply(decoded_bytes, matches);
        let re_encoded = base64::engine::general_purpose::STANDARD.encode(&replaced);
        let new_value = format!("Basic {re_encoded}");
        if let Ok(hv) = http::HeaderValue::from_str(&new_value) {
            headers.insert(name.clone(), hv);
        }
        redactions
    } else {
        // other Authorization schemes — scan full value
        scan_raw_header_value(headers, name, value_bytes)
    }
}

/// scan raw header value bytes and update header if replacement occurred
fn scan_raw_header_value(
    headers: &mut http::HeaderMap,
    name: &http::HeaderName,
    value_bytes: &[u8],
) -> Vec<Redaction> {
    let bytes = Bytes::copy_from_slice(value_bytes);
    let matches = crate::detection::scan_field(&bytes);
    if matches.is_empty() {
        return vec![];
    }
    let (replaced, redactions) = crate::replacement::apply(bytes, matches);
    if let Ok(hv) = http::HeaderValue::from_bytes(&replaced) {
        headers.insert(name.clone(), hv);
    }
    redactions
}
