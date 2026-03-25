# Proxy Integration Spec

**Purpose:** Documents exactly which lines in `hudsucker.rs` change and how the new modules wire into the proxy handler. Intended as the integration guide for the v1.1 implementer.

---

## 1. Purpose

This document bridges the core pipeline specs (detection, replacement, content routing) and the existing proxy code. It specifies the before/after at each `hudsucker.rs` call site, body buffering requirements, Content-Length recalculation, gzip delegation, SSE streaming path, event_bus changes, signed request bypass, and error recovery.

---

## 2. Components Modified

| Component | Change | Type |
|-----------|--------|------|
| `src/hudsucker.rs` | Replace `do_match` call with `content_router::process_request`; add `content_router::process_response` | MODIFY |
| `src/regex_patterns.rs` → `src/patterns/mod.rs` | Rename module; update to load `combined.yaml` via `include_str!`; expose `COMBINED`, `RULES`, `NormalizedRule` | MODIFY/RENAME |
| `src/event_bus.rs` | Add `fake_value: String` field to `RedactedEntry`; remove `matched_text` from event bus | MODIFY |
| `Cargo.toml` | Add runtime deps (`uuid`, `base64`, `url`, `fake` or `rand`) and build deps (`toml`, `serde_yml`) | MODIFY |
| `build.rs` | New file — normalization pipeline (documented in BUILD-PIPELINE.md) | NEW |
| `src/detection/` | New module (`mod.rs`, `types.rs`) — documented in DETECTION-PIPELINE.md | NEW |
| `src/replacement/` | New module (`mod.rs`, `types.rs`, `replacers.rs`) — documented in REPLACEMENT-PIPELINE.md | NEW |
| `src/content_router/` | New module — documented in CONTENT-ROUTING.md | NEW |

---

## 3. handle_request Integration

The new call site in `hudsucker.rs` `handle_request`:

```rust
// Before (current):
let (replaced_bytes, matched) = do_match(bytes.clone()).await;

// After:
let (replaced_bytes, redactions) = content_router::process_request(
    req.headers(),
    bytes,
).await;
```

Full step-by-step sequence after receiving a request body:

**a. Buffer full request body to `Bytes`**

Already done via current body accumulation in `handle_request`. No change needed here.

**b. Check for signed request bypass**

Before calling the content router:
```rust
if is_signed_request(req.headers()) {
    log::warn!("[bleep] skipping replacement: signed request detected");
    return RequestOrResponse::Request(req);  // forward unchanged
}
```
See section 9 for signed request detection logic.

**c. Call content router**

```rust
let (replaced_bytes, redactions) = content_router::process_request(
    req.headers(),
    bytes,
).await;
```

Returns `(Bytes, Vec<Redaction>)`.

**d. Fast path: no redactions**

```rust
if redactions.is_empty() {
    return RequestOrResponse::Request(rebuild_request(req, original_bytes));
}
```

Forward original bytes unchanged. Content-Length is unchanged.

**e. Slow path: redactions present**

```rust
// 1. Update Content-Length
if let Some(cl) = req.headers_mut().get_mut(CONTENT_LENGTH) {
    *cl = HeaderValue::from(replaced_bytes.len());
}

// 2. Emit to event bus (fake values only — original values NOT on event bus)
for redaction in &redactions {
    event_bus.send(ProxyEvent::Redacted(RedactedEntry {
        rule_id: redaction.rule_id.clone(),
        category: redaction.category.clone(),
        subcategory: redaction.subcategory.clone(),
        severity: redaction.severity.clone(),
        fake_value: redaction.fake.clone(),
        // original value is NOT here — only in the JSONL audit file
    })).ok();
}

// 3. Write JSONL audit entry with original values (local disk only)
request_logger.log_redactions(&redactions).await;

// 4. Forward replaced bytes
rebuild_request(req, replaced_bytes)
```

---

## 4. handle_response Integration

Response scanning detects cases where the LLM echoes back injected content from the request.

**Non-streaming responses:**

Same pattern as `handle_request` — buffer the full response body, call `content_router::process_response(headers, body)`, update Content-Length, emit events, log.

```rust
// in handle_response:
let (replaced_bytes, redactions) = content_router::process_response(
    res.headers(),
    body_bytes,
).await;
if !redactions.is_empty() {
    // update Content-Length, emit events, log
}
```

**Streaming SSE responses:**

For responses where `is_streaming_request(req)` returned true, the response body arrives as a stream of SSE frames. Do NOT buffer the full streaming response — that defeats streaming latency.

Route to the SSE frame handler in the content router:
```rust
// content_router::process_sse_stream handles per-frame scan + replace + re-emit
content_router::process_sse_stream(res, event_sink).await
```

The SSE streaming path processes each frame independently:
1. Buffer bytes until `\n\n` frame boundary
2. Scan and replace the `data:` field JSON payload
3. Re-emit the modified frame immediately
4. Continue to next frame

---

## 5. Body Buffering Spec

| Body type | Buffering strategy |
|-----------|-------------------|
| Non-streaming request body | Full buffer to `Bytes` — already implemented in current `handle_request` |
| Non-streaming response body | Full buffer to `Bytes` — must be added for response scanning |
| Streaming SSE response | Per-frame buffer only — do NOT buffer full stream; `SseFrameParser` handles incomplete chunks |

`is_streaming_request(req)` in `proxy.rs` is the gate:
- If streaming: route to SSE per-frame path
- If non-streaming: buffer and scan full body

Current `is_streaming_request` checks `Accept: text/event-stream` header. Verify this is set on all Anthropic and OpenAI streaming requests.

---

## 6. Content-Length Recalculation

```rust
// after content_router returns replaced_bytes:
if !redactions.is_empty() {
    if let Some(cl) = req.headers_mut().get_mut(CONTENT_LENGTH) {
        *cl = HeaderValue::from(replaced_bytes.len());
    }
    // if Content-Length was absent (chunked encoding), do not add it
}
```

Rule: if `Content-Length` was present, overwrite it. If absent (chunked `Transfer-Encoding`), leave it absent — do not add a `Content-Length` header that was not there.

This applies identically to response bodies.

---

## 7. Gzip Handling at Proxy Level

The content router handles gzip decompression and recompression internally (see `CONTENT-ROUTING.md` section 10). The proxy layer does not need to know about compression encoding.

The content router's `ProcessedBody` return value includes the new Content-Encoding if recompression occurred:

```rust
pub struct ProcessedBody {
    pub bytes: Bytes,
    pub redactions: Vec<Redaction>,
    pub content_encoding: Option<String>,  // Some("gzip") if recompressed, None if unchanged
}
```

At the proxy layer:
```rust
if let Some(encoding) = processed.content_encoding {
    req.headers_mut().insert(CONTENT_ENCODING, HeaderValue::from_str(&encoding)?);
}
```

This keeps gzip logic inside the content router where it belongs.

---

## 8. event_bus Changes

The `RedactedEntry` struct in `src/event_bus.rs` must be modified:

```rust
// Before (current):
pub struct RedactedEntry {
    pub rule_id: String,
    pub category: String,
    pub matched_text: String,  // original matched value — SECURITY RISK on event bus
}

// After:
pub struct RedactedEntry {
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub fake_value: String,    // what was substituted — safe for TUI and event bus consumers
    // matched_text removed — original value goes only to JSONL audit file
}
```

Security note: removing `matched_text` from the event bus prevents the original secret from flowing to the TUI process over the TCP socket. The TUI displays what was replaced (fake value), not what the original was. Original values are retained only in the JSONL audit file on local disk (file permissions: owner-only, `0o600`).

---

## 9. Signed Request Bypass

Some requests carry a cryptographic signature over the body. Modifying the body invalidates the signature. For v1.0, Bleep is Anthropic-only — this guard protects users who accidentally route other HTTPS traffic through the proxy.

Detection: check for AWS SigV4 signature pattern in `Authorization` header:

```rust
fn is_signed_request(headers: &HeaderMap) -> bool {
    headers.get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("AWS4-HMAC-SHA256 Credential="))
        .unwrap_or(false)
}
```

If matched: skip content router entirely, log warning, forward original request unchanged:
```
[bleep] skipping replacement: AWS SigV4 signed request (rule: signed-request-bypass)
```

This guard exists per PITFALLS.md Pitfall 9: API signature invalidation. A developer who routes AWS API calls through Bleep would otherwise receive signature mismatch errors.

---

## 10. Error Recovery

If `content_router::process_request` returns an error (decompression failed, JSON became invalid after replacement, replacer panic):

```rust
match content_router::process_request(headers, bytes.clone()).await {
    Ok((replaced_bytes, redactions)) => {
        // normal path
    }
    Err(e) => {
        log::error!("[bleep] processing error: {e}, forwarding original body");
        // forward original bytes unchanged
        return RequestOrResponse::Request(rebuild_request(req, bytes));
    }
}
```

Rules:
- Never propagate a processing error to the upstream LLM — proxy must always forward something
- Never drop the request or return a 5xx to the downstream client
- The upstream LLM receives either the redacted body or the original body; never an error from Bleep's internal processing
- Log the error with enough context (rule_id if available) for debugging

---

## Links

- Content routing implementation — see `docs/arch/CONTENT-ROUTING.md`
- Detection pipeline — see `docs/arch/DETECTION-PIPELINE.md`
- Replacement pipeline — see `docs/arch/REPLACEMENT-PIPELINE.md`
- Safety invariants (no invalid JSON, Content-Length correctness) — see `docs/arch/SAFETY-INVARIANTS.md`
