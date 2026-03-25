# Replacement Pipeline Spec

**Purpose:** Defines the `replacement` module — its public API, core types, algorithm, and constraints. This module has one responsibility: take original body bytes and a `Vec<Match>` from `detection::scan`, splice fake values at match spans right-to-left, and return modified bytes plus a `Redaction` log.

---

## 1. Purpose and Scope

The replacement module receives the original bytes and the sorted match list from detection. It generates fake values for each match and splices them into a mutable buffer, processing from the end of the buffer backward. It returns the modified bytes and a list of `Redaction` records for the audit log and event bus.

Responsibilities:
- Generate a fake value for each match by dispatching on `replacement_type`
- Maintain a per-request dedup map so the same raw value always maps to the same fake within one request
- Splice fakes into the byte buffer right-to-left (highest span.start first) to avoid offset invalidation
- Return `(modified_bytes, Vec<Redaction>)` — the Redaction list is the forward map for de-anonymization

Not responsible for:
- Updating `Content-Length` (caller's responsibility)
- Logging (caller passes Redaction list to audit logger)
- Event bus emission (caller handles)
- JSON validity verification (content router handles)

---

## 2. Module Structure

```
src/replacement/
├── mod.rs       — pub fn apply, internal splice logic
├── types.rs     — Redaction struct
└── replacers.rs — pure fns: fake_email, fake_api_key, fake_ssn, etc.
```

---

## 3. Core Types

```rust
pub struct Redaction {
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    pub original: String,       // UTF-8 lossy decode of match.raw; for audit log only
    pub fake: String,            // substituted value written into body
    pub span: Range<usize>,      // byte position in original body (before any splicing)
}
```

Field notes:

| Field | Note |
|-------|------|
| `original` | Pre-replacement value preserved for the JSONL audit trail. **Must NOT be logged to any external output** — only the JSONL file for local audit. Never sent to the event bus. |
| `fake` | The substituted value. Safe for event bus and TUI display. |
| `span` | Byte position in the *original* body, before any modification. Useful for correlating audit entries. |

---

## 4. apply() Function Spec

```rust
pub fn apply(body: Bytes, matches: Vec<Match>) -> (Bytes, Vec<Redaction>)
```

**Precondition:** `matches` must be sorted by `span.start` descending, as returned by `detection::scan`.

Algorithm:

**a. Early return**

If `matches` is empty, return `(body, vec![])` immediately. No allocation.

**b. Build per-request dedup map**

```rust
let mut dedup: HashMap<Vec<u8>, String> = HashMap::new();
```

Keyed on raw matched bytes (`Vec<u8>`), value is the generated fake string. This ensures the same raw value always maps to the same fake within one request — see section 5 for rationale.

**c. Convert to mutable buffer**

```rust
let mut buffer: Vec<u8> = body.into();
```

**d. Process each match (right-to-left)**

For each match in `matches` (already sorted descending by `span.start`):

1. Check if `match.rule.replacement_type == "passthrough"`. If so, skip splice — no `Redaction` entry is created for passthrough matches. Continue to next match.
2. Look up `match.raw` in the dedup map. If found, use the cached fake. If not found, call `replacers::generate(&match.rule.replacement_type, &match.rule.id)` to generate a new fake, insert into dedup map.
3. Convert fake string to bytes.
4. Splice: `buffer.splice(match.span.start..match.span.end, fake_bytes.iter().copied())`
5. Record `Redaction { rule_id: match.rule.id.clone(), category: match.rule.category.clone(), subcategory: match.rule.subcategory.clone(), severity: match.rule.severity.clone(), original: String::from_utf8_lossy(&match.raw).into_owned(), fake: fake.clone(), span: match.span.clone() }`.

**e. Return**

```rust
(Bytes::from(buffer), redactions)
```

**Why right-to-left (descending span.start):** Splicing at position N changes the byte length of the buffer, which shifts all positions > N. By processing from the end of the buffer backward, every unprocessed span remains valid throughout the loop. Processing left-to-right would cause offset drift after the first splice.

---

## 5. Per-Request Dedup Map

Design:

| Property | Value |
|----------|-------|
| Key | `Vec<u8>` — raw matched bytes, not the rule_id |
| Value | `String` — the generated fake |
| Scope | One map per `apply()` call, discarded when the request completes |
| Allocation | `HashMap::new()` with no initial capacity; typical request has < 10 matches |

Rationale: LLM coherence. If a prompt references the same AWS key twice (at two different positions), both occurrences must become the same fake string. The LLM sees a consistent context — the same identifier appears twice as expected. Using rule_id as the key would fail this because two different rules might match the same raw value.

Same raw value = same fake. Different raw values = different fakes (unless they collide in the random generator, which is acceptable).

---

## 6. Forward Map for Response De-Anonymization

The returned `Vec<Redaction>` is the forward map:

```
redaction.fake → redaction.original
```

For each `Redaction` in the list, the fake value maps back to the original value. This enables response de-anonymization: scan the LLM response for any fake values that appear in the Redaction list and replace each fake with its original.

**v1.0 status:** De-anonymization is not implemented in this milestone. However, the data is captured. The `Vec<Redaction>` must be passed to the response handler alongside the replaced bytes for future use.

Implementation pattern for a future de-anonymization pass:

```rust
// build reverse map: fake -> original
let reverse_map: HashMap<&str, &str> = redactions.iter()
    .map(|r| (r.fake.as_str(), r.original.as_str()))
    .collect();

// scan response body for fake values using the reverse map
// (simple string replacement, not regex — fakes are known exact strings)
```

---

## 7. replacers::generate Spec

```rust
pub fn generate(replacement_type: &str, rule_id: &str) -> String
```

This function is a match dispatch over all 16 `replacement_type` values:

```rust
match replacement_type {
    "faker_email"      => fake_email(),
    "faker_phone"      => fake_phone(),
    "faker_ssn"        => fake_ssn(),
    "faker_cc_luhn"    => fake_cc_luhn(),
    "faker_iban"       => fake_iban(),
    "faker_uuid"       => fake_uuid(),
    "faker_ipv4"       => fake_ipv4(),
    "faker_aws_key"    => fake_aws_key(),
    "faker_github_pat" => fake_github_pat(),
    "faker_jwt"        => fake_jwt(),
    "faker_api_key"    => fake_api_key(),
    "faker_db_conn"    => fake_db_conn(),
    "faker_url_cred"   => fake_url_cred(),
    "fpe_numeric"      => fake_fpe_numeric(),
    "generic_random"   => fake_generic_random(),
    "passthrough"      => unreachable!("passthrough is checked by apply() before calling generate"),
    _                  => format!("[REDACTED:{rule_id}]"),  // unknown type: fallback
}
```

Constraints on `generate()`:
- No async
- No I/O
- No external calls
- Pure: same inputs produce structurally similar (but randomly valued) outputs
- Each arm calls a dedicated pure fn in `replacers.rs`

The `passthrough` arm is unreachable because `apply()` checks for passthrough before calling `generate()`. If `generate()` is called with `"passthrough"`, it is a programming error.

Unknown `replacement_type` returns `[REDACTED:{rule_id}]` — current behavior as safe fallback. This should not occur in production since build.rs validates all `replacement_type` values at compile time.

---

## 8. JSON Safety Constraint

All generated fake values **must be safe for substitution inside a JSON string value**.

Prohibited characters in fake values:
- Unescaped `"` (double quote)
- Unescaped `\` (backslash)
- ASCII control characters (0x00–0x1F)

Each replacer fn is responsible for ensuring its output is JSON-safe. Motivation: `replacement::apply` operates on raw bytes. If the body is JSON and a replacement value contains an unescaped `"`, the resulting bytes are invalid JSON. This would corrupt the LLM request.

The JSON handler in `content_router` validates JSON after replacement as a defense-in-depth check (see `CONTENT-ROUTING.md`), but the primary defense is that replacers never produce unsafe characters.

---

## 9. Module Constraints

Same as detection:

**Must NOT import:**
- `hudsucker` — no proxy types
- `axum` — no HTTP framework types
- `reqwest` — no HTTP client types
- `tokio` — no async runtime

**Must be:**
- Fully synchronous
- Free of I/O
- Free of network calls

---

## 10. Integration Points

**Non-streaming request:**

```rust
// in hudsucker.rs handle_request, after body is buffered to Bytes:
let matches = detection::scan(&bytes);
if matches.is_empty() { /* forward unchanged */ }
let (replaced_bytes, redactions) = replacement::apply(bytes, matches);
// recalculate Content-Length header with replaced_bytes.len()
// pass redactions to audit logger
// pass redactions to event_bus (fake values only, not originals)
```

**Streaming SSE response:**

`apply()` is called per SSE frame, not on the full stream buffer. The dedup map is per-frame in streaming mode — this means the same secret appearing across two different SSE frames may produce two different fakes. This is an acceptable limitation in v1.0. Cross-frame dedup is a v1.x enhancement.

---

## 11. Invariants

The following guarantees must hold:

| Invariant | Statement |
|-----------|-----------|
| Every span replaced exactly once | Every byte range in `Vec<Match>` is either spliced or explicitly skipped (`passthrough`). No span is silently ignored. |
| No overlap in output Redaction spans | Guaranteed by `detection::scan` overlap resolution. `apply()` trusts this. |
| Content-Length not updated | `apply()` returns modified bytes. Updating Content-Length is the caller's responsibility. `apply()` never touches HTTP headers. |
| Error recovery | If `generate()` panics for any reason, `apply()` should return the original unmodified bytes. Two options: (a) wrap with `std::panic::catch_unwind`; (b) return `Result<(Bytes, Vec<Redaction>), Error>` and let the caller handle. Implementation choice for v1.1 — document both here. The safety invariant is: never emit partially-replaced bytes on error. |

---

## Links

- Detection pipeline (produces `Vec<Match>`) — see `docs/arch/DETECTION-PIPELINE.md`
- Replacement type enum (all 16 values) — see `docs/schema/REPLACEMENT-TYPES.md`
- Content routing (calls apply, handles JSON validation) — see `docs/arch/CONTENT-ROUTING.md`
