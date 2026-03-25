# Detection Pipeline Spec

**Purpose:** Defines the `detection` module — its public API, core types, algorithm, and constraints. This module has one responsibility: scan raw bytes and return all match spans. It does no replacement, no I/O, and imports no proxy types.

---

## 1. Purpose and Scope

The detection module receives a byte slice and returns a list of all matches found by the compiled rule set. It is the entry point to the pattern-matching pipeline.

Responsibilities:
- Apply the AhoCorasick keyword pre-filter to fast-reject bodies without sensitive content
- Run per-rule regex matching on the byte slice
- Apply entropy filtering to discard low-entropy matches
- Resolve overlapping spans
- Return matches sorted in right-to-left (descending span.start) order for downstream replacement

Not responsible for:
- Modifying any bytes
- Reading from or writing to I/O
- Logging (caller logs)
- Filtering by confidence level (caller decides the threshold)

---

## 2. Module Structure

```
src/detection/
├── mod.rs    — pub fn scan, pub use types::Match
└── types.rs  — Match struct, re-exports NormalizedRule from patterns module
```

---

## 3. Core Types

```rust
pub struct Match {
    pub rule: Arc<NormalizedRule>,  // ref to compiled rule; Arc avoids cloning large structs
    pub span: Range<usize>,          // byte offsets into original body; start inclusive, end exclusive
    pub raw: Vec<u8>,                // matched bytes captured from original body (for audit log)
}
```

Field rationale:

| Field | Rationale |
|-------|-----------|
| `rule: Arc<NormalizedRule>` | Rule metadata needed by replacement (`replacement_type`, `id`) and audit log (`category`, `severity`). `Arc` because `RULES` static owns the compiled rules and we avoid copying. |
| `span: Range<usize>` | Byte offsets required for right-to-left splice in replacement. Must be byte offsets (not char offsets) because `regex::bytes` operates on raw bytes. |
| `raw: Vec<u8>` | Original matched bytes captured before any replacement, required for audit log and per-request dedup map. |

---

## 4. scan() Function Spec

```rust
pub fn scan(body: &[u8]) -> Vec<Match>
```

No async. No side effects. No panics on valid input.

Algorithm:

**a. Combined pre-filter**

Run `COMBINED.is_match(body)` where `COMBINED` is the `AhoCorasick` automaton built from all keyword strings across all rules. If this returns false, return an empty `Vec<Match>` immediately — fast path for bodies with no sensitive content.

**b. Per-rule matching**

For each rule in `RULES` (compiled `Vec<(Arc<NormalizedRule>, Regex)>` with pre-compiled per-rule `regex::bytes::Regex`):

1. If `rule.keywords` is non-empty and none of `rule.keywords` appear as substrings in `body`, skip rule (inner pre-filter for rules with specific keywords).
2. Run `rule.regex.find_iter(body)`, collect all matches.
3. For each match: apply entropy filter if `rule.entropy.is_some()`. Compute Shannon entropy of the matched bytes. If `entropy(matched_bytes) < rule.entropy.unwrap()`, discard the match.
4. For remaining matches: construct `Match { rule: Arc::clone(&rule_arc), span: m.start()..m.end(), raw: body[m.start()..m.end()].to_vec() }`.

**c. Collect**

Collect all `Match` values across all rules into a single `Vec<Match>`.

**d. Resolve overlapping spans**

Sort by `span.start` ascending, then walk the list. For any match whose span is entirely contained within a preceding longer match, remove it (the longer/outer match wins — it captures more context). See section 7 for exact rules.

**e. Sort descending**

Sort the final `Vec<Match>` by `span.start` descending. This right-to-left order is required by `replacement::apply` so that splicing at position N does not invalidate offsets for earlier positions (positions < N).

**f. Return**

Return the sorted `Vec<Match>`.

---

## 5. Confidence Scoring

`NormalizedRule.confidence` is set during `build.rs` normalization from source metadata. `scan()` does **not** filter by confidence — it returns all matches. Filtering by `--min-confidence` is the caller's responsibility (proxy layer, not scan).

| Source | Confidence derivation |
|--------|----------------------|
| gitleaks | Inferred: prefix-anchored pattern = `high`, context-anchored = `medium`, generic = `low` (excluded at curation time) |
| secrets-patterns-db | Use the `confidence` field directly (`high` / `medium` / `low`) |
| nosey-parker | All curated NP rules default to `high` (NP is the primary high-precision source, security-engineer-curated) |
| hand-authored | Set explicitly per rule; EU PII patterns are `low` |

---

## 6. Entropy Calculation

Shannon entropy over the byte distribution of the matched slice:

```
H = -sum(p_i * log2(p_i))
    for each unique byte value where p_i = count(byte_value) / len(bytes)
```

Applied to `match.raw` bytes only, not the full body. This is standard Shannon entropy over the byte value distribution.

A low-entropy match (e.g., `AAAAAAAAAAAAAAAA`) indicates the pattern fired on a repeated or constant sequence that is unlikely to be a real secret. The entropy threshold (`rule.entropy: Option<f64>`) is set per rule during `build.rs` normalization.

`rule.entropy = None` means the entropy filter is disabled for that rule — `scan()` skips the check entirely.

---

## 7. Overlap Resolution Rules

When two matches A and B have overlapping spans:

| Case | Rule |
|------|------|
| A.span fully contains B.span | Keep A, drop B — longer span wins (more context captured) |
| A.span and B.span partially overlap | Keep both — different rules may legitimately fire on adjacent content |
| A.span == B.span (identical spans) | Keep higher-confidence rule; if equal confidence, apply source priority: nosey-parker > gitleaks > secrets-patterns-db > hand-authored |

The resolution algorithm:
1. Sort all matches by `span.start` ascending, then by `span.len()` descending (longer spans first within the same start).
2. Walk the sorted list. For each match, compare against all preceding matches. If the current match's span is entirely within any preceding match's span, remove the current match.
3. After dedup, the remaining list is sorted by `span.start` descending for return.

---

## 8. Multi-line Patterns

Multi-line patterns (PEM keys, JWTs spanning multiple lines) use the `(?s)` dot-matches-newline flag in their regex definition. These patterns are tagged `multiline` in `INTERNAL-SCHEMA.md`.

No special handling is needed in `scan()` — `regex::bytes` handles the `(?s)` flag. However:

- Multi-line patterns cannot benefit from the single-line keyword pre-filter optimization. If `COMBINED.is_match()` fires (because of any keyword in the body), multi-line patterns run their full regex against the full body.
- The `regex::bytes::RegexBuilder` used during compile time must enable dot-matches-newline when the pattern has the `multiline` tag. This is a `build.rs` concern.

---

## 9. Module Constraints

**Must NOT import:**
- `hudsucker` — no proxy types
- `axum` — no HTTP framework types
- `reqwest` — no HTTP client types
- `tokio` — no async runtime
- Any async executor

**Must be:**
- Fully synchronous — `scan` is a blocking function
- Free of I/O
- Free of logging (caller logs after inspecting `Vec<Match>`)

**Test coverage required:**
- `test_no_match_empty_body` — empty body returns empty Vec
- `test_no_match_clean_body` — body with no patterns returns empty Vec
- `test_single_match` — body with one known pattern returns one Match with correct span
- `test_overlapping_matches` — body that fires two rules with overlapping spans keeps the longer one
- `test_entropy_filter` — low-entropy match is discarded when entropy threshold is set
- `test_keyword_prefilter_shortcircuit` — body with no keywords skips the regex entirely

---

## 10. Integration Point

How `hudsucker.rs` calls the detection module:

```rust
// in handle_request, after body is buffered to Bytes:
let matches = detection::scan(&bytes);
if matches.is_empty() {
    // fast path: no sensitive content, forward unchanged
    return forward_unchanged(req);
}
// slow path: pass matches to replacement::apply
let (replaced_bytes, redactions) = replacement::apply(bytes, matches);
```

The body bytes are borrowed by `scan()` as `&[u8]`. Ownership of the `Bytes` is retained by the caller for passing to `replacement::apply`.

---

## Links

- `NormalizedRule` fields — see `docs/schema/INTERNAL-SCHEMA.md`
- Replacement pipeline (consumes `Vec<Match>`) — see `docs/arch/REPLACEMENT-PIPELINE.md`
- Build pipeline (compiles `COMBINED` and `RULES`) — see `docs/arch/BUILD-PIPELINE.md`
