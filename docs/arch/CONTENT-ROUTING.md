# Content-Type Routing Spec

**Purpose:** Defines the `content_router` module — the adapter between hudsucker's HTTP types and the format-agnostic `detection::scan` / `replacement::apply`. The content router extracts scannable bytes from a request or response body regardless of encoding, routes to a format-specific handler, and reassembles the body in the original format.

---

## 1. Purpose and Scope

The content router's responsibility:
1. Extract scannable bytes from an HTTP body, accounting for encoding (gzip, deflate) and content type (JSON, form, multipart, SSE)
2. Call `detection::scan` and `replacement::apply` on the extracted bytes
3. Reassemble the body in its original format
4. Update Content-Length to reflect the modified byte length

The content router is the only module that knows about `Content-Type`, `Content-Encoding`, and HTTP body structure. Neither `detection` nor `replacement` see these types.

---

## 2. Routing Decision Tree

Applied to every incoming body in sequence:

**Step 1 — Check Content-Encoding:**

| Value | Action |
|-------|--------|
| `gzip` | Decompress with flate2 GzDecoder before processing; recompress after replacement |
| `deflate` | Decompress with flate2 DeflateDecoder before processing; recompress after replacement |
| `br` (Brotli) | Not supported in v1.0 — pass through unchanged, log warning: `"[bleep] unsupported Content-Encoding: br, passing through"` |
| (absent or other) | Raw bytes, proceed as-is |

**Step 2 — Check Content-Type:**

| Value | Handler |
|-------|---------|
| `application/json` | JSON handler |
| `application/x-www-form-urlencoded` | URL-encoded handler |
| `multipart/form-data` | Multipart handler |
| `text/plain` or `text/*` | Plain-text handler |
| `text/event-stream` | SSE streaming handler |
| `image/*`, `audio/*`, `video/*`, `application/octet-stream` | Skip scanning — pass through unchanged |
| Unknown or absent | Treat as plain-text |

**Step 3 — After routing:**

Scan extracted bytes, apply replacements, return reassembled body.

---

## 3. JSON Handler Spec

1. Parse body with `serde_json::from_slice(&body_bytes)` to validate the body is valid JSON before scanning.
2. If parse fails: log warning `"[bleep] JSON parse failed, falling back to plain-text handler"`, route to plain-text handler.
3. Pass **raw bytes** (not the parsed structure) to `detection::scan` — regex operates on raw bytes; JSON structure is not needed for matching.
4. Call `replacement::apply(body_bytes, matches)` to get `replaced_bytes`.
5. Validate modified bytes: `serde_json::from_slice(&replaced_bytes)`. If invalid: log error `"[bleep] replacement produced invalid JSON for rule {rule_id}, reverting"` and return original unmodified bytes (safety invariant: never emit invalid JSON).
6. Return `replaced_bytes`.

Note: the JSON-safe constraint on fake values (no unescaped `"` or `\`) is a requirement on the replacer functions, not on this handler. This handler validates the result as defense-in-depth.

---

## 4. URL-Encoded Handler Spec

1. Split body on `&` to get `key=value` pairs.
2. For each value: percent-decode with the `urlencoding` crate (or equivalent percent-decode from `form_urlencoded`).
3. Concatenate decoded values as bytes, scan with `detection::scan`.
4. Apply `replacement::apply` on decoded value bytes.
5. Percent-encode the modified values back.
6. Reassemble the body as `key1=value1&key2=value2` etc.

Edge case: if the decoded + re-encoded form differs from the original (e.g., whitespace encoding style), use the re-encoded form. This is acceptable — the URL-encoded representation is semantically equivalent.

Note: URL-encoded bodies are typically short form data. If a field contains a secret (e.g., an API key submitted in a form), it will be matched and replaced.

---

## 5. Multipart Handler Spec

1. Parse the `boundary` parameter from the `Content-Type` header (e.g., `Content-Type: multipart/form-data; boundary=----FormBoundary7MA4YWxkTrZu0gW`).
2. Split the body on the boundary to extract individual parts.
3. For each part: inspect the part's `Content-Type` header.
   - Text parts (`text/plain`, `application/json`, `text/*`): scan and replace as appropriate handler.
   - Binary parts (`image/*`, `application/octet-stream`, etc.): skip — pass through unchanged.
4. Reassemble the multipart body with the same boundary.
5. Update the outer Content-Length.

Scope note: multipart in LLM API context is primarily file upload. For v1.0, scan only text parts. Binary part scanning (OCR for images, text extraction for PDFs) is deferred to the OCR milestone.

---

## 6. Plain-Text Handler Spec

1. Scan raw bytes directly via `detection::scan(&body_bytes)`.
2. Apply `replacement::apply(body_bytes, matches)`.
3. No structural validation needed.
4. Return `replaced_bytes`.

This is the simplest path and the fallback for unknown content types.

---

## 7. SSE Streaming Handler Spec

SSE (Server-Sent Events) is the format used by OpenAI and Anthropic for streaming LLM responses. The body is a stream of frames.

**SSE frame format:**

```
event: <type>\n
id: <id>\n
data: <json_payload>\n
\n
```

Frames are separated by `\n\n`. The `event:`, `id:`, and `retry:` lines are optional. The `data:` field is required and typically contains a JSON payload. The stream ends with `data: [DONE]`.

**Architecture: per-frame processing**

The SSE handler maintains a stateful `SseFrameParser` that buffers bytes until complete frames are available. Per-frame processing:

1. Parse the `data:` field from the frame.
2. If `data: [DONE]` — SSE stream end marker, emit unchanged.
3. Otherwise: parse JSON payload, route to JSON handler, reassemble frame with updated `data:` field, emit immediately.

Frame boundaries may split across TCP chunks — the parser must handle partial frames by buffering until `\n\n` is seen. Emit each completed frame immediately after replacement. Do NOT buffer the full SSE stream.

**SseFrameParser state machine:**

```
struct SseFrameParser {
    buffer: Vec<u8>,
}

impl SseFrameParser {
    fn push(&mut self, chunk: &[u8]) -> Vec<SseFrame>
    // - append chunk to buffer
    // - split on b"\n\n" boundaries
    // - return complete frames; keep incomplete tail in buffer

    fn flush(&mut self) -> Option<SseFrame>
    // - if buffer is non-empty, return as final partial frame (end of stream)
    // - called when upstream closes the connection
}
```

**Dedup map scope in streaming:** One dedup map per frame (not per stream) in v1.0. This means the same secret appearing across two different SSE frames may produce two different fake values — cross-frame dedup is a v1.x enhancement. Document this limitation in the audit log.

---

## 8. Header Scanning Spec

Header scanning is a separate pass, run after body scanning.

**Headers to scan:**

| Header | Treatment |
|--------|-----------|
| `Authorization` | Scan full value; special cases below |
| `X-Api-Key` | Scan raw value |
| `X-Auth-Token` | Scan raw value |
| `X-Secret` | Scan raw value |
| Any header whose name (case-insensitive) contains `key`, `secret`, `token`, or `password` | Scan raw value |

**Special cases for Authorization:**

- `Authorization: Bearer <token>` — scan the token portion only (the value after `Bearer `).
- `Authorization: Basic <base64>` — base64-decode the value, scan the decoded `user:password` string, re-encode after replacement. Note: decoded form is `username:password`; if password is replaced, re-encode with `base64::engine::general_purpose::STANDARD`.

**Exclusions:** Do not scan standard informational headers: `Content-Type`, `Content-Length`, `User-Agent`, `Accept`, `Host`, `Accept-Encoding`, `Cache-Control`, etc.

After replacement: update the header value in the request. Header scanning does not affect Content-Length (body length unchanged).

---

## 9. Content-Length Invariant

After any body modification, the proxy **must** update Content-Length to the new body byte length.

Rule:
- If `Content-Length` header is present: overwrite with `replaced_bytes.len()`.
- If `Content-Length` is absent (chunked encoding): do not add it.
- If body is unchanged (`redactions.is_empty()`): do not touch `Content-Length`.

```rust
// after replacement::apply returns replaced_bytes:
if !redactions.is_empty() {
    if let Some(cl) = headers.get_mut(CONTENT_LENGTH) {
        *cl = HeaderValue::from(replaced_bytes.len());
    }
}
```

This applies to both request and response bodies. Failure to update Content-Length causes HTTP clients to truncate or hang (see PITFALLS.md Pitfall 1).

---

## 10. Gzip/Deflate Handling

Expanded from routing decision step 1:

**Decompression:**
- gzip: `flate2::read::GzDecoder::new(body_bytes.as_ref())`; read to end
- deflate: `flate2::read::DeflateDecoder::new(body_bytes.as_ref())`; read to end
- On decompression failure: do NOT pass raw compressed bytes to scanner. Return original body unchanged and log warning: `"[bleep] decompression failed for Content-Encoding {encoding}, passing through"`. Never silently pass compressed bytes to scan.

**Recompression after replacement:**
- gzip: `flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default())`
- deflate: `flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default())`
- Write `replaced_bytes` to encoder, flush.
- Update Content-Length with the new compressed length.
- Preserve the original `Content-Encoding` header value (do not change it).

---

## 11. Out of Scope for v1.0

The following are explicitly deferred:

| Feature | Status | Notes |
|---------|--------|-------|
| Brotli decompression (`Content-Encoding: br`) | Deferred | Pass through unchanged; log warning |
| Binary content type scanning | Deferred to OCR milestone | `image/*`, `audio/*`, etc. |
| Cross-frame SSE dedup | v1.x enhancement | Per-frame dedup only in v1.0 |
| Base64 decode-scan inside JSON fields | v1.x enhancement | Nested base64 secrets (e.g., a base64-encoded AWS key inside a JSON string field) |

The base64 nested scan risk: a JSON body may contain a field whose value is a base64-encoded blob that itself contains a secret (e.g., a Kubernetes service account file). Detection will not fire on the base64-encoded form. Documented as known FP gap per FEATURES.md edge cases.

---

## Links

- Detection pipeline (called for each extracted byte block) — see `docs/arch/DETECTION-PIPELINE.md`
- Replacement pipeline (called after scan) — see `docs/arch/REPLACEMENT-PIPELINE.md`
- Proxy integration (calls content router from hudsucker) — see `docs/arch/PROXY-INTEGRATION.md`
