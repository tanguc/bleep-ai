# Fake Generators Spec

**Purpose:** Defines the output contract for every replacer function. For each `replacement_type`, documents the exact output format/pattern, which Rust crate or algorithm produces it, JSON-safety status, and realism level.

---

## 1. Purpose

This document specifies what each replacer function produces. Implementers of `src/replacement/replacers.rs` must produce output matching these specs. Any deviation breaks the JSON-safety contract or undermines the realism policy.

---

## 2. Realism Policy

Fake values must be format-shaped but **not** cryptographically valid or usable as real credentials.

The tradeoff:
- Fake values must be realistic enough that the LLM produces coherent output (it sees a plausible email, not gibberish).
- Fake values must NOT pass validation checks of real services (a Luhn-valid card with an attacker-controlled number, a GitHub PAT that could be attempted against the GitHub API).

Design principle: **use reserved/fictional ranges and obvious markers** — values that are format-correct but immediately recognizable as fake by any engineer who looks at them.

| Concern | Approach |
|---------|----------|
| Email domains | `@example.com` — RFC 2606 reserved for documentation; never a real mailbox |
| Phone numbers | `+1-555-010-XXXX` — 555-010x range is US fictitious per NANP/ITU |
| SSN | `000-00-XXXX` — SSA never assigns area number 000 |
| IP addresses | `203.0.113.0/24` — TEST-NET-3 per RFC 5737; never routable |
| API key markers | `BLEEP` inserted after real service prefix — human-readable signal |
| IBAN | `BLEEP` as fake bank code — recognizable as synthetic |
| JWT | `"bleep":true` in header — signals non-real to any inspector |

---

## 3. Per-Type Spec Table

| `replacement_type` | Output format | Crate / algorithm | JSON-safe | Notes |
|--------------------|---------------|-------------------|-----------|-------|
| `faker_email` | `{word}@example.com` | `rand` + word list, or `fake` v5 with domain override | YES | RFC 2606 domain; `+` in local part is valid and JSON-safe |
| `faker_phone` | `+1-555-010-XXXX` | `rand` — 4 random digits for XXXX | YES | 555-010x is US fictitious range |
| `faker_ssn` | `000-00-{4 digits}` | `rand` — 4 random digits | YES | SSA area number 000 is permanently unassigned |
| `faker_cc_luhn` | 16-digit, prefix `4000-00XX-XXXX-XXXX` | `rand` + Luhn check-digit calculation | YES | Stripe test card range; Luhn-valid to avoid re-trigger |
| `faker_iban` | `GB00BLEEP0000000000000` | string literal | YES | `BLEEP` as bank code signals non-real |
| `faker_uuid` | UUID v4, e.g. `550e8400-e29b-41d4-a716-446655440000` | `uuid` crate, `Uuid::new_v4()` | YES | Valid UUID v4; acceptable because UUIDs are not credentials |
| `faker_ipv4` | `203.0.113.{0-255}` | `rand` — last octet | YES | RFC 5737 TEST-NET-3 documentation range |
| `faker_aws_key` | `AKIABLEEP{11 random chars}` (20 chars total) | `rand` + `[A-Z0-9]` charset | YES | `AKIA` prefix preserved; `BLEEP` signals fake; 20-char total matches AWS format |
| `faker_github_pat` | `ghp_BLEEP{31 random chars}` (40 chars total) | `rand` + `[A-Za-z0-9]` charset | YES | `ghp_` prefix preserved; `BLEEP` signals fake; 40-char total matches GitHub PAT |
| `faker_jwt` | `{header}.{payload}.{signature}` | manual base64url encoding | YES | `"bleep":true` in header; valid 3-segment structure |
| `faker_api_key` | 32 lowercase hex chars | `rand` + hex charset `[0-9a-f]` | YES | Generic fallback for SaaS tokens without dedicated faker |
| `faker_db_conn` | `{scheme}://bleep:bleep@bleep-fake-db.invalid:{port}/dbname` | `url` crate for parse+reconstruct | YES | `.invalid` TLD per RFC 2606; `bleep` credentials |
| `faker_url_cred` | Replace `user:password@` with `bleep:bleep@`; preserve rest of URL | `url` crate | YES | Same scheme and host; only credentials replaced |
| `fpe_numeric` | Same digit count as input, FF1/AES-256 encrypted | `fpe` crate (v1.1 concern) | YES | Requires key management; see note below |
| `generic_random` | Random alphanumeric, same length as matched value | `rand` + charset matching input | YES | Length-preserving fallback |
| `passthrough` | No output — no splice performed | — | N/A | Caller skips splice when `replacement_type == "passthrough"` |

---

## 4. Detailed Specs

### faker_email

- Format: `{random_word}@example.com`
- Domain: `example.com` (RFC 2606 — reserved for documentation, never a real mailbox; alternatively `bleep.invalid` which is also RFC 2606 reserved and more explicit)
- Decision: use `@example.com` — more widely recognized as a test domain
- Implementation options:
  - Option A: `fake` crate v5, generate `FreeEmail` locale, then replace domain: `format!("{}@example.com", local_part)`
  - Option B: `rand` + a fixed word list (30-40 common first names), `format!("{}@example.com", word_list[rng.gen_range(..)])`
- Note: the `+` character in the local part (e.g., `user+tag@example.com`) is valid email syntax and JSON-safe
- JSON-safe: YES — no double-quotes, backslashes, or control characters in well-formed email addresses

---

### faker_phone

- Format: `+1-555-010-XXXX` where XXXX is 4 random digits (`rand`)
- The `555-010x` range (`555-0100` through `555-0199`) is reserved for fictional use in North American media per NANP
- Alternative: `555-555-XXXX` is also fictitious but `555-010x` is the more precisely defined range
- JSON-safe: YES

---

### faker_ssn

- Format: `000-00-{4 random digits}`, e.g. `000-00-1234`
- The `000` area number is permanently unassigned by the SSA — no valid SSN starts with `000`
- Do NOT generate valid-range SSNs (001–899, excluding 666) — that risks producing a real person's SSN
- JSON-safe: YES

---

### faker_cc_luhn

- Format: 16 digits, starting with `4000-00` prefix (Stripe's test card range), remaining digits random, last digit is Luhn check digit
- Example: `4000-0012-3456-7894`
- Luhn algorithm (5 lines of Rust):
  ```rust
  fn luhn_check_digit(digits: &[u8]) -> u8 {
      let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
          if i % 2 == 0 { let v = d as u32 * 2; if v > 9 { v - 9 } else { v } }
          else { d as u32 }
      }).sum();
      ((10 - (sum % 10)) % 10) as u8
  }
  ```
- Luhn validity is intentional: the replacement itself must not re-trigger the cc detection rule. If the fake CC number fails Luhn, a strict CC regex with Luhn validation would match it again. The `4000-00` prefix distinguishes it from real Visa cards (which use different prefixes) — any payments engineer recognizes this as a test card number.
- JSON-safe: YES (digits only)

---

### faker_iban

- Format: `GB00BLEEP0000000000000` (fixed string)
- GB country code; `00` check digits (technically invalid IBAN check, which is intentional — a valid IBAN check digit would make this indistinguishable from a real UK IBAN by format); `BLEEP` as bank code; `0000000000000` as account number
- Rationale: IBAN structure (country + 2 check digits + BBAN) is preserved; `BLEEP` bank code signals non-real
- JSON-safe: YES

---

### faker_uuid

- Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` (UUID v4 standard format)
- Crate: `uuid` (already in Cargo.toml per project research), `Uuid::new_v4().to_string()`
- Realism note: UUID v4 is indistinguishable from real UUIDs by format — this is acceptable because UUIDs are not credentials and their exposure does not represent a security risk
- JSON-safe: YES

---

### faker_ipv4

- Format: `203.0.113.{0–255}` where the last octet is a random value from `rand`
- `203.0.113.0/24` is TEST-NET-3 per RFC 5737 — this range is documentation-only and never routable on the public internet
- Other documentation ranges for reference: `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2)
- JSON-safe: YES

---

### faker_aws_key

- Format: `AKIABLEEP` + 11 random uppercase alphanumeric chars = 20 chars total
- `AKIA` is the AWS IAM access key prefix (real format); `BLEEP` signals fake to a human reader; 11 more chars to reach 20 total
- Charset: `[A-Z0-9]` — matches real AWS key charset
- JSON-safe: YES

---

### faker_github_pat

- Format: `ghp_BLEEP` + 31 random alphanumeric chars = 40 chars total
- `ghp_` is the GitHub fine-grained PAT prefix (real format); `BLEEP` signals fake; 31 more chars for 40 total
- Charset: `[A-Za-z0-9]`
- Note: GitHub also uses `github_pat_` prefix for newer fine-grained tokens and `ghp_` for classic. Use `ghp_` as the most recognizable prefix.
- JSON-safe: YES

---

### faker_jwt

- Format: three base64url-encoded segments: `header.payload.signature`
- Header object: `{"alg":"HS256","typ":"JWT","bleep":true}` — the `"bleep":true` field signals non-real
- Payload object: `{"sub":"bleep-fake","iat":1000000000}` — epoch `1000000000` is 2001-09-08, well in the past; no real JWT would use this timestamp
- Signature: 43 random base64url characters (matches HS256 signature length)
- Base64url charset: `[A-Za-z0-9_-]` with no padding (`=`)
- Crate: `base64` crate (`base64::engine::general_purpose::URL_SAFE_NO_PAD`)
- Construct manually — no JWT library needed:
  ```rust
  let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT","bleep":true}"#);
  let payload = base64url_encode(br#"{"sub":"bleep-fake","iat":1000000000}"#);
  let signature: String = rng.sample_iter(base64url_charset).take(43).collect();
  format!("{}.{}.{}", header, payload, signature)
  ```
- JSON-safe: YES — base64url uses only `[A-Za-z0-9_-]` and the segments are joined by `.` — no characters special in JSON

---

### faker_api_key

- Format: 32 random lowercase hex characters, e.g. `a3f1b2c4d5e6...` (32 chars)
- Charset: `[0-9a-f]`
- Crate: `rand`
- Use for: all SaaS API tokens without a dedicated faker (stripe, sendgrid, slack, openai, anthropic, gitlab, npm, pypi, telegram, generic)
- JSON-safe: YES

---

### faker_db_conn

- Format: `{scheme}://bleep:bleep@bleep-fake-db.invalid:{original_port}/{original_dbname}`
- Example: `postgresql://bleep:bleep@bleep-fake-db.invalid:5432/mydb`
- Parse original URI with the `url` crate to extract: scheme, port, database name (path)
- Replace: username → `bleep`, password → `bleep`, host → `bleep-fake-db.invalid`
- Preserve: scheme, port, database name, query parameters
- `.invalid` TLD is RFC 2606 reserved — never resolves via DNS
- Crate: `url` crate for parse and reconstruct
- JSON-safe: YES if the URL crate produces well-formed URIs (no unescaped special chars); the `url` crate handles percent-encoding

---

### faker_url_cred

- Format: Replace `{user}:{password}@` with `bleep:bleep@`; preserve the rest of the URL unchanged
- Example: `https://admin:secret123@api.example.com/v1` → `https://bleep:bleep@api.example.com/v1`
- Crate: `url` crate
- JSON-safe: YES

---

### fpe_numeric

- Algorithm: FF1 format-preserving encryption (AES-256) per NIST SP 800-38G
- Input: the matched digit string; output: a different digit string of the same length
- Crate: `fpe` crate (if available and maintained); otherwise implement FF1 directly with `aes` crate
- Key management: requires an AES-256 key. **Key management is a v1.1 architecture concern.** The schema specifies the intent (`replacement_type: fpe_numeric`) but key derivation (from a session seed, from an env var, etc.) is not decided here.
- v1.0 status: rules that use `fpe_numeric` should fall back to `generic_random` if no FPE key is configured, with a warning log.
- JSON-safe: YES (digits only)

---

### generic_random

- Format: random string of the same length as the matched value; charset matches the input:
  - Input is all hex → output charset: `[0-9a-f]`
  - Input is all alpha → output charset: `[A-Za-z]`
  - Input is alphanumeric → output charset: `[A-Za-z0-9]`
  - Input is mixed → output charset: `[A-Za-z0-9]`
- Crate: `rand`
- Use as: fallback when no specific faker applies; also used for EU PII patterns (uk-nin, pl-pesel, fr-insee, de-taxid) where format-only matching is used without check-digit validation
- JSON-safe: YES (alphanumeric only)

---

### passthrough

- No output. The match is detected but not replaced.
- The `apply()` function in the replacement pipeline skips the splice when `replacement_type == "passthrough"`.
- No `Redaction` record is created for passthrough matches.
- Used for: `infra/ipv4` (detection only, passthrough) and debugging.

---

## 5. JSON Safety Audit

All fakers produce JSON-safe output. Verification:

| Faker | Risk | Status |
|-------|------|--------|
| faker_email | None — no special chars in `word@example.com` | SAFE |
| faker_phone | None — digits, `+`, `-` only | SAFE |
| faker_ssn | None — digits and `-` only | SAFE |
| faker_cc_luhn | None — digits only | SAFE |
| faker_iban | None — letters and digits | SAFE |
| faker_uuid | None — hex digits and `-` | SAFE |
| faker_ipv4 | None — digits and `.` | SAFE |
| faker_aws_key | None — uppercase letters and digits | SAFE |
| faker_github_pat | None — alphanumeric | SAFE |
| faker_jwt | None — base64url is `[A-Za-z0-9_-]` and `.`; all JSON-safe | SAFE |
| faker_api_key | None — lowercase hex | SAFE |
| faker_db_conn | Potential: `url` crate must not produce unescaped `"` or `\` | SAFE via `url` crate percent-encoding |
| faker_url_cred | Same as faker_db_conn | SAFE via `url` crate |
| fpe_numeric | None — digits only | SAFE |
| generic_random | None — alphanumeric only | SAFE |

Unit test requirement for each replacer:
```rust
// assert fake is JSON-safe:
let fake = generate("faker_email", "test-rule");
serde_json::from_str::<serde_json::Value>(&format!("\"{}\"", fake))
    .expect("fake value must be JSON-safe");
```

---

## 6. Crate Additions Required

| Crate | Version | Purpose |
|-------|---------|---------|
| `fake` | `"5"` | faker_email (optional; `rand` + word list is simpler) |
| `uuid` | `{ version = "1", features = ["v4"] }` | faker_uuid — confirm already in Cargo.toml |
| `base64` | `"0.22"` | faker_jwt base64url encoding |
| `url` | `"2"` | faker_db_conn, faker_url_cred |
| `fpe` | TBD | fpe_numeric — evaluate crate maturity before v1.1 |
| `rand` | already present | all random value generation |

---

## 7. Testing Requirements

For each replacer, unit tests must assert:

1. **Format correctness:** output matches the documented format pattern (e.g., SSN format regex `^\d{3}-\d{2}-\d{4}$`).
2. **JSON-safety:** `serde_json::from_str::<serde_json::Value>(&format!("\"{}\"", output)).is_ok()`.
3. **No re-trigger:** output does NOT match the original detection rule's regex (prevents fake-value feedback loops where the fake is detected as a new secret).

The no-re-trigger test is particularly important for faker_cc_luhn (Luhn-valid output could re-trigger CC rules) and faker_aws_key (must not match `AKIA[A-Z0-9]{16}` with the BLEEP insertion avoiding the pattern).

---

## Links

- Replacement pipeline (dispatches to fakers) — see `docs/arch/REPLACEMENT-PIPELINE.md`
- Replacement type enum (all 16 values) — see `docs/schema/REPLACEMENT-TYPES.md`
- Safety invariants (JSON validity, no double-replacement) — see `docs/arch/SAFETY-INVARIANTS.md`
