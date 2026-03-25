# Safety Invariants

**Purpose:** Enumerates the behavioral guarantees the Bleep pipeline must maintain at all times. Each invariant has a name, a statement (what must be true), a detection condition (how to verify it is violated), a recovery action (what to do when violated), and a corresponding test.

---

## 1. Purpose

Safety invariants are non-negotiable properties. If any invariant is violated, the system is in an incorrect state regardless of other functionality working correctly. Each invariant corresponds to one or more unit tests that serve as CI gates.

---

## 2. Invariant List

### INV-01: No Invalid JSON Output

**Statement:** If the original request or response body was valid JSON, the modified body must also be valid JSON after replacement.

**Detection condition:** `serde_json::from_slice(&replaced_bytes)` returns an error when `serde_json::from_slice(&original_bytes)` succeeded.

**Recovery action:** Discard `replaced_bytes`, forward original unmodified bytes. Log error with the `rule_id` of the replacement that caused invalidity:
```
[bleep] INV-01 violation: replacement produced invalid JSON (rule: {rule_id}), reverting to original body
```

**Implementation note:** The JSON handler in the content router validates JSON after replacement (defense-in-depth). The primary prevention is that all replacer functions produce JSON-safe output (no unescaped `"` or `\`).

**Test:** `test_json_valid_after_replacement` — for every JSON body test case (including bodies with secrets, emails, API keys), assert `serde_json::from_slice(result).is_ok()`.

---

### INV-02: No Double Replacement

**Statement:** No byte range in the body is replaced more than once. Fake values substituted by one rule are never re-scanned by detection.

**Detection condition:** A known fake value pattern (e.g., `ghp_BLEEP`, `000-00-`, `AKIABLEEP`, `@example.com`) appears in the body after replacement and is then flagged by another scan pass.

**Recovery action:** This invariant is maintained by architecture, not by defensive recovery:
- `detection::scan` is called exactly once per request on the original bytes, before any mutation.
- `replacement::apply` mutates a copy of the bytes; the scan result is derived from the pre-mutation buffer.
- The result is never re-scanned.

If a double-replacement is detected in testing (e.g., the fake email triggers an email rule), the root cause is an overly broad detection rule — fix the rule, not the pipeline.

**Implementation guarantee:** `apply()` receives a pre-computed `Vec<Match>` from a single scan of the original bytes. No scan runs on the `replaced_bytes` output.

**Test:** `test_no_double_replacement` — body with a known pattern that would match; after replacement, assert the replaced body does NOT produce matches when scanned again. Assert `detection::scan(&replaced_bytes).is_empty()` or that no fake values appear in subsequent match spans.

---

### INV-03: Content-Length Correctness

**Statement:** After any body modification, the forwarded `Content-Length` header value equals the byte length of the forwarded body.

**Detection condition:** `content_length_header_value != replaced_bytes.len()` after any replacement.

**Recovery action:** Always overwrite `Content-Length` after replacement when `!redactions.is_empty()`. Rule:
- If `Content-Length` was present in original headers: overwrite with `replaced_bytes.len()`.
- If `Content-Length` was absent (chunked `Transfer-Encoding`): do not add it.
- If body was unchanged (`redactions.is_empty()`): do not modify `Content-Length`.

Never forward the original `Content-Length` when the body has been modified (see PITFALLS.md Pitfall 1).

**Test:** `test_content_length_updated` — for each request/response forwarding test case, assert the `Content-Length` header value exactly equals `body.len()` after replacement.

---

### INV-04: Fallback on Processing Error

**Statement:** If any step in the detection-routing-replacement pipeline fails (decompression error, JSON parse error, replacer panic), the proxy forwards the original unmodified body. It never drops the request, returns a 5xx to the downstream client, or emits partially-replaced bytes.

**Detection condition:** Processing error occurs and downstream receives a 5xx response, an empty body, or a partially-replaced body.

**Recovery action:** The processing pipeline wraps with `catch` (either `Result` propagation or `std::panic::catch_unwind`):
```rust
match content_router::process_request(headers, bytes.clone()).await {
    Ok(result) => { /* normal path */ }
    Err(e) => {
        log::error!("[bleep] INV-04: processing error: {e}, forwarding original");
        forward_original(req, bytes)
    }
}
```

The upstream LLM gets either the redacted body or the original body. Never a Bleep internal error.

**Test:** `test_fallback_on_decompression_error` — send a body with `Content-Encoding: gzip` containing invalid (non-gzip) bytes; assert proxy returns original body unchanged and does not 5xx.

---

### INV-05: Original Values Not Transmitted to Unprotected Sinks

**Statement:** Original matched values (pre-replacement secrets, PII) must never appear in the event bus (TUI socket), stdout/stderr logs, or any output visible to non-audit consumers.

**Detection condition:** `matched_text` or equivalent raw value present in a `ProxyEvent` emitted to the event bus; or present in stdout/stderr log output.

**Recovery action:** `RedactedEntry` on the event bus carries only `rule_id`, `category`, `subcategory`, `severity`, and `fake_value`. Raw original values go only to the JSONL audit file:
- JSONL audit file: local disk, `0o600` permissions (owner read/write only)
- Event bus (`broadcast::channel`): fake values only
- stdout/stderr: rule_id and category only, never original value

**Test:** `test_event_bus_no_raw_values` — intercept all `ProxyEvent::Redacted` emissions during a test with a known secret; assert no `ProxyEvent` field contains the original secret string.

**CI status:** Partially automated. The test above catches the event bus case. Full coverage requires code review to ensure no logging call includes the original value — this is also a code review gate.

---

### INV-06: Compressed Body Fully Decompressed Before Scanning

**Statement:** If `Content-Encoding` indicates compression (`gzip`, `deflate`), the body is decompressed before `detection::scan` is called. Scanning is never run against compressed bytes.

**Detection condition:** Detection produces zero matches on a body known to contain secrets, while `Content-Encoding: gzip` (or `deflate`) is present.

**Recovery action:**
- Content router checks `Content-Encoding` before passing bytes to scan.
- On successful decompression: pass decompressed bytes to scan.
- On decompression failure: invoke INV-04 (forward original, log error). Never pass compressed bytes to scan.

```
[bleep] INV-06: decompression failed for Content-Encoding gzip, forwarding original
```

**Test:** `test_gzip_body_scanned` — construct a gzip-encoded body containing a known secret; assert detection fires and replacement occurs. Also test with a malformed gzip body that decompression error triggers INV-04 fallback.

---

### INV-07: SSE Streaming Not Buffered to Completion

**Statement:** For streaming (SSE) responses, the first token arrives at the downstream client within 100ms of the first SSE frame being received from the upstream, even with replacement active.

**Detection condition:** Downstream client receives no output until the full LLM response is complete (buffering occurred). Measured as time-to-first-byte on the downstream connection.

**Recovery action:**
- SSE path uses `SseFrameParser` for per-frame scanning and immediate re-emission.
- The full-body buffer path is used only for non-streaming responses.
- `is_streaming_request(req)` in `proxy.rs` is the gate — if this returns true, the SSE path must be used.

**Test:** `test_sse_first_token_latency` — integration test with a mock upstream that sends SSE frames with a 50ms delay between frames; assert first frame arrives at downstream within 100ms of upstream sending it. Mark as stretch goal for v1.1 test suite (requires mock infrastructure).

**CI status:** Integration test; may require mocking upstream. Stretch goal for v1.1 — unit tests for `SseFrameParser` correctness are the primary CI gate.

---

### INV-08: Replacement Span Coverage

**Statement:** Every `Match` span returned by `detection::scan` is either spliced (replacement applied) or explicitly skipped (`passthrough` replacement_type). No span is silently ignored.

**Detection condition:** A `Redaction` record is not created for a `Match` that was not `passthrough`.

**Recovery action:** `apply()` processes every match in the `Vec<Match>`. The only way a match produces no output in the `Redaction` list is if `replacement_type == "passthrough"`, which is explicitly handled as a skip with no splice.

```
assert!(redactions.len() + passthrough_count == matches.len())
```

**Test:** `test_all_matches_processed` — a body with N known patterns; assert `redactions.len() + passthrough_count == N`. Verify no match span is silently dropped.

---

## 3. Invariant-to-Test Mapping

| Invariant | Test name | Test type | CI gate |
|-----------|-----------|-----------|---------|
| INV-01 | `test_json_valid_after_replacement` | Unit | Yes — always run |
| INV-02 | `test_no_double_replacement` | Unit | Yes — always run |
| INV-03 | `test_content_length_updated` | Unit | Yes — always run |
| INV-04 | `test_fallback_on_decompression_error` | Unit | Yes — always run |
| INV-05 | `test_event_bus_no_raw_values` | Unit | Yes — always run; also code review gate |
| INV-06 | `test_gzip_body_scanned` | Unit | Yes — always run |
| INV-07 | `test_sse_first_token_latency` | Integration | Stretch goal for v1.1 |
| INV-08 | `test_all_matches_processed` | Unit | Yes — always run |

---

## 4. Invariant Verification in CI

**Unit test gates (always run):** INV-01, INV-02, INV-03, INV-04, INV-05, INV-06, INV-08.

**Code review gate (INV-05):** No automated test can fully audit that every log call omits original values. Reviewers must check: any new logging statement, any new event bus emit, any new TUI display code — verify original secret is not present.

**Integration test (INV-07):** Requires a mock upstream SSE server. Mark as stretch goal for v1.1 test suite. The `SseFrameParser` unit tests cover correctness of frame parsing; the integration test covers the latency property.

---

## Links

- Replacement pipeline invariants section — see `docs/arch/REPLACEMENT-PIPELINE.md` (section 11)
- Content routing error handling — see `docs/arch/CONTENT-ROUTING.md`
- Proxy error recovery — see `docs/arch/PROXY-INTEGRATION.md` (section 10)
