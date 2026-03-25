# Gitleaks TOML → Internal Schema Field Mapping

**Source file:** `rules/vendor/gitleaks/gitleaks.toml`
**Format:** TOML `[[rules]]` blocks
**Total rules in vendored file:** ~170 (as of commit 8863af47d64c3681422523e36837957c74d4af4b)
**Included in curated manifest:** 30 rules (see `docs/analysis/CURATED-MANIFEST.md`)
**License:** MIT

---

## Source Format Reference

Each rule in `gitleaks.toml` is a TOML `[[rules]]` block. Fields available per rule:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | slug identifier, e.g. `stripe-access-token` |
| `description` | string | yes | human-readable sentence describing the secret |
| `regex` | string | yes | RE2-compatible pattern (all gitleaks rules verified RE2-compat in Phase 1) |
| `entropy` | float | no | minimum Shannon entropy of matched string; e.g. `3.8` |
| `keywords` | string[] | no | lowercase substring pre-filter; at least one must appear in body before regex is tried |
| `secretGroup` | int | no | capture group index for the secret value (0 = full match) |
| `path` | string | no | regex applied to file path, not content |
| `tags` | string[] | no | freeform metadata tags |
| `[[rules.allowlist]]` | block | no | per-rule allowlist with `regexes`, `paths`, `commits`, `stopwords` |

The file also has a top-level `[allowlist]` block (paths, regexes, stopwords) that applies globally to all rules. This is not a per-rule field — see Global Allowlist Note below.

### Representative Raw TOML Snippet

```toml
[[rules]]
id = "stripe-access-token"
description = "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
regex = '''\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)'''
entropy = 2
keywords = [
    "sk_test",
    "sk_live",
    "sk_prod",
    "rk_test",
    "rk_live",
    "rk_prod",
]
```

---

## Field Mapping Table

| Gitleaks Field | Type | Internal Field | Transform | Notes |
|----------------|------|----------------|-----------|-------|
| `id` | string | `id` | prefix with `gl.`: `gl.{id}` | e.g. `gl.stripe-access-token` |
| `description` | string | `description` | copy verbatim | serves as human description |
| `regex` | string | `regex` | copy verbatim | all gitleaks patterns verified RE2-compatible in Phase 1 |
| `entropy` | float | `entropy` | copy as float; omit field if absent | observed range in file: 2.0–5.0; `null` (disabled) when not present |
| `keywords` | string[] | `keywords` | copy as list; default `[]` if absent | used as substring pre-filter |
| `tags` | string[] | `tags` | copy as list; default `[]` if absent | freeform metadata |
| `secretGroup` | int | — | **DROPPED** | build.rs resolves capture groups at normalization time; not a runtime schema concern |
| `path` | string | — | **DROPPED** | file-path scanning is not a proxy concept; bleep operates on HTTP body content |
| `[[rules.allowlist]]` | block | — | **DROPPED** | allowlisting is a detection engine concern; encode as build.rs filter hints, not per-rule schema |
| (none) | — | `name` | derive from `description`: use `description` verbatim as the name; fall back to `id` slug if description is absent | gitleaks `description` is the closest equivalent to a human name |
| (none) | — | `category` | assigned from curated manifest subcategory→category lookup | always `secret` for gitleaks rules (no PII or infra patterns in gitleaks) |
| (none) | — | `subcategory` | assigned from `docs/analysis/CURATED-MANIFEST.md` | e.g. `stripe`, `aws`, `github`, `anthropic` |
| (none) | — | `confidence` | inferred using confidence inference rules below | gitleaks has no confidence field; must be derived |
| (none) | — | `source` | hardcoded `gitleaks` | always `gitleaks` for any rule normalized from this file |
| (none) | — | `replacement_type` | derived from subcategory per `REPLACEMENT-TYPES.md` | e.g. `faker_api_key` for `stripe`, `faker_aws_key` for `aws` |
| (none) | — | `checksum_type` | `luhn` only for `cc` subcategory; `null` otherwise | no gitleaks rules are in the `cc` subcategory |

---

## Confidence Inference Rules

Gitleaks has no confidence field. Confidence must be inferred by build.rs during normalization using the following three-tier heuristic.

### Tier 1 — High Confidence

Pattern is **prefix-anchored**: starts with a known, unique token prefix that is vendor-specific.

Indicators:
- Regex begins with a literal prefix like `AKIA`, `ghp_`, `sk-ant-api`, `ops_eyJ`, `AGE-SECRET-KEY-1`, etc.
- The prefix alone is sufficient to uniquely identify the secret type
- False positive rate is very low because the prefix is not a common string

Examples from gitleaks.toml:
- `1password-secret-key`: starts with `A3-`
- `1password-service-account-token`: starts with `ops_eyJ`
- `age-secret-key`: starts with `AGE-SECRET-KEY-1`
- `stripe-access-token`: starts with `sk_test`, `sk_live`, `rk_*`

Assign `confidence: high` for prefix-anchored token formats.

### Tier 2 — Medium Confidence

Pattern is **context-anchored**: uses surrounding keywords or assignment context to locate a secret-looking string, rather than matching on the secret format itself.

Indicators:
- Regex contains assignment operators: `=`, `:`, `=>`, `||`
- Regex looks for a keyword in the neighborhood of a generic token string
- Pattern uses `(?i)[\w.-]{0,50}?(?:keyword)(?:...)` structure

Examples from gitleaks.toml:
- `adafruit-api-key`: context-anchored on keyword `adafruit` + generic 32-char alphanum
- `adobe-client-id`: context-anchored on keyword `adobe` + 32-char hex
- `airtable-api-key`: context-anchored on keyword `airtable` + 17-char alphanum

Assign `confidence: medium` for context-anchored assignment patterns.

### Tier 3 — Low Confidence (excluded)

Pattern is **generic**: no vendor prefix, no keyword context, matches any token-shaped string.

These should not appear in the curated manifest (the manifest EXCLUDE decision filters them out). If encountered in normalization, log a warning and skip.

**Summary table:**

| Pattern Type | Confidence | Indicator |
|--------------|------------|-----------|
| Prefix-anchored (`AKIA`, `ghp_`, `sk_`, etc.) | `high` | regex begins with vendor-specific literal prefix |
| Context-anchored (`keyword + assignment + token`) | `medium` | regex contains keyword context and assignment operators |
| Generic (no prefix, no context) | `low` | pattern matches arbitrary token-shaped strings — exclude from schema |

---

## Global Allowlist Note

`gitleaks.toml` contains a top-level `[allowlist]` block with three sub-fields:
- `paths`: list of path regexes that globally suppress all rules (e.g. skip `node_modules/`, binary files)
- `regexes`: list of value regexes that globally suppress matches (e.g. skip `$ENV_VAR` placeholders)
- `stopwords`: list of literal strings whose presence suppresses a match

**This is NOT a per-rule field.** It is NOT normalized into the internal schema. It is a concern for:
1. The detection engine (runtime allowlist logic)
2. Build.rs preprocessing (may encode as engine configuration, not rule-level YAML)

The internal schema has no equivalent of a global allowlist. Per-rule `[[rules.allowlist]]` blocks are also dropped (see Field Mapping Table). Allowlist logic is entirely outside the normalized rule schema.

---

## Before/After Normalization Example

### Source: raw TOML (rules/vendor/gitleaks/gitleaks.toml)

```toml
[[rules]]
id = "stripe-access-token"
description = "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
regex = '''\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)'''
entropy = 2
keywords = [
    "sk_test",
    "sk_live",
    "sk_prod",
    "rk_test",
    "rk_live",
    "rk_prod",
]
```

Fields present in source: `id`, `description`, `regex`, `entropy`, `keywords`
Fields absent from source: `secretGroup`, `path`, `tags`, `[[rules.allowlist]]`

### Normalized internal YAML output (rules/patterns.yaml)

```yaml
- id: gl.stripe-access-token
  name: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
  category: secret
  subcategory: stripe
  source: gitleaks
  confidence: high
  regex: '\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60''"\s;]|\\[nr]|$)'
  keywords: ["sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"]
  entropy: 2.0
  tags: []
  checksum_type: null
  replacement_type: faker_api_key
  description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
  severity: high
```

**Transform decisions applied:**
- `id`: `stripe-access-token` → `gl.stripe-access-token` (namespace prefix)
- `description`: copied verbatim; also used as `name` (gitleaks description = closest name equivalent)
- `regex`: copied verbatim (RE2-compatible, verified in Phase 1)
- `entropy`: `2` → `2.0` (float)
- `keywords`: copied verbatim
- `secretGroup`: absent — dropped (not in schema)
- `path`: absent — dropped (not in schema)
- `tags`: absent from source → default `[]`
- `confidence`: inferred `high` — pattern is prefix-anchored (`sk_test`, `sk_live`, `rk_*` prefixes are distinctive Stripe token formats)
- `category`: `secret` — assigned from curated manifest
- `subcategory`: `stripe` — assigned from curated manifest
- `source`: `gitleaks` — hardcoded
- `checksum_type`: `null` — stripe subcategory does not use Luhn
- `replacement_type`: `faker_api_key` — derived from `secret/stripe` per REPLACEMENT-TYPES.md
- `severity`: `high` — derived from `confidence: high`

---

## Common Pitfalls

### Pitfall 1: secretGroup confusion

**What goes wrong:** Developer reads `secretGroup: 1` and tries to add a `secret_group` field to the internal schema, or passes it through as metadata.

**Why it's wrong:** `secretGroup` tells the gitleaks engine which regex capture group contains the actual secret (vs surrounding context). In the internal schema, build.rs resolves capture groups at normalization time. The runtime schema contains only the final normalized regex — group indexing is a build-time concern, not a runtime field.

**Rule:** DROPPED. Never carry `secretGroup` into the internal schema.

### Pitfall 2: Confidence assignment defaults

**What goes wrong:** All gitleaks rules get `confidence: medium` by default because "we're not sure."

**Why it's wrong:** Many gitleaks rules are highly reliable prefix-anchored formats. Defaulting everything to `medium` understates the detection quality of these patterns and may cause downstream logic (severity assignment, alerting thresholds) to treat high-precision patterns as medium-precision.

**Rule:** Apply the three-tier confidence inference heuristic. Prefix-anchored = `high` is the rule, not the exception. Only context-anchored patterns get `medium`.

### Pitfall 3: Global allowlist treated as per-rule data

**What goes wrong:** Developer sees the top-level `[allowlist]` in gitleaks.toml and tries to normalize it into each rule's `tags` or as a new schema field.

**Why it's wrong:** The global allowlist applies to all rules uniformly — it is not per-rule data. It belongs in the detection engine configuration, not the rule schema. The per-rule `[[rules.allowlist]]` blocks are also dropped for the same reason.

**Rule:** Both `[allowlist]` and `[[rules.allowlist]]` are DROPPED from the internal schema. Document their existence as build.rs preprocessing input if needed.
