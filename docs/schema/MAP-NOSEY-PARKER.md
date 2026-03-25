# Nosey Parker YAML → Internal Schema Field Mapping

**Source files:** `rules/vendor/nosey-parker/rules/*.yml` (one YAML file per service area)
**Format:** YAML `rules:` list (each file is a list of rule objects)
**Role:** Nosey Parker is the PRIMARY source for secrets detection — security-engineer-curated, highest precision, built-in `examples`/`negative_examples` for self-testing
**License:** Apache-2.0
**Internal schema reference:** [INTERNAL-SCHEMA.md](./INTERNAL-SCHEMA.md)

---

## Source Format Reference

Each Nosey Parker YAML file contains a top-level `rules:` list. Every rule object may contain these fields:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | human-readable name, e.g. `AWS API Key` |
| `id` | string | yes | dot-namespaced slug, e.g. `np.aws.1` — globally unique within source |
| `pattern` | string | yes | RE2-compatible; multiline patterns use YAML `\|` block scalar with `(?x)` verbose mode |
| `references` | string[] | no | documentation URLs only |
| `categories` | string[] | no | capability flags: `api`, `identifier`, `fuzzy`, `secret` — NOT the taxonomy |
| `examples` | string[] | no | strings that MUST match the pattern (positive test cases) |
| `negative_examples` | string[] | no | strings that MUST NOT match (negative test cases) |

### Representative Rule — Single-line Pattern

This is `np.aws.1` (AWS API Key) from `rules/vendor/nosey-parker/rules/aws.yml`, showing all fields with a single-line pattern:

```yaml
- name: AWS API Key
  id: np.aws.1

  pattern: '\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b'

  references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

  categories:
  - api
  - identifier

  examples:
  - 'A3T0ABCDEFGHIJKLMNOP'
  - 'AKIADEADBEEFDEADBEEF'

  negative_examples:
  - 'A3T0ABCDEFGHIJKLMNO'
  - 'A3T0ABCDEFGHIjklmnop'
  - '======================'
```

### Representative Rule — Multiline Verbose Pattern

This is `np.aws.2` (AWS Secret Access Key) from the same file, showing the `(?x)` verbose mode with YAML `|` block scalar:

```yaml
- name: AWS Secret Access Key
  id: np.aws.2

  pattern: |
    (?x)(?i)
    \b
    aws_? (?:secret)? _? (?:access)? _? (?:key)?
    ["'']?
    \s{0,30}
    (?::|=>|=)
    \s{0,30}
    ["'']?
    ([a-z0-9/+=]{40})
    (?: [^a-z0-9/+=] | $ )

  categories:
  - api
  - fuzzy
  - secret

  examples:
  - 'aws_secret_access_key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  - 'aws_secret_access_key => aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

  negative_examples:
  - 'export AWS_SECRET_ACCESS_KEY=ded7db27a4558e2ea9bbf0bf36ae0e8521618f366c'
```

The `|` block scalar is YAML's literal block style — the pattern string includes every newline and leading space as written. The `(?x)` flag tells the RE2 engine to treat unescaped whitespace and `#`-prefixed text as comments, so the extra spacing is discarded at match time.

---

## Field Mapping Table

| NP Field | Type | Internal Field | Transform | Notes |
|----------|------|----------------|-----------|-------|
| `id` | string | `id` | copy verbatim | NP IDs already namespace-prefixed (`np.aws.1`, `np.github.1`, etc.); globally unique; no additional prefix needed |
| `name` | string | `name` | copy verbatim | |
| `pattern` | string | `regex` | copy verbatim; for multiline `(?x)` patterns, preserve as YAML block scalar (`\|`) | do NOT flatten multiline patterns to a single string; see multiline handling section |
| `categories` | string[] | `tags` | copy NP category values as tag strings | CRITICAL: maps to `tags`, NOT to `category`; see pitfall section below |
| `references` | string[] | — | DROPPED from runtime schema | documentation URLs only; no internal equivalent; may be preserved as comments in the vendored source file |
| `examples` | string[] | — | DROPPED from runtime schema | preserved in `rules/patterns-test-fixtures.yaml` for build-time validation; see test fixtures section |
| `negative_examples` | string[] | — | DROPPED from runtime schema | same as `examples`; see test fixtures section |
| (none) | — | `category` | assigned from curated manifest subcategory→category lookup | two-level taxonomy: `secret` \| `pii` \| `infra`; NEVER copied from NP `categories` |
| (none) | — | `subcategory` | assigned from CURATED-MANIFEST.md | e.g. `aws`, `github`, `stripe`, `email`, `ssn` |
| (none) | — | `confidence` | `high` for prefix-anchored patterns; `medium` for `fuzzy`-tagged patterns | see confidence assignment rules below |
| (none) | — | `entropy` | omitted (`null`) | NP provides no entropy guidance at the field level; `null` means entropy check disabled |
| (none) | — | `keywords` | omitted (`[]`) | may be derived from NP `examples` prefix characters if needed; empty = no pre-filter |
| (none) | — | `checksum_type` | `luhn` for `pii/cc` subcategory; `null` otherwise | |
| (none) | — | `description` | `""` | NP has no description field |
| (none) | — | `severity` | derived from `confidence`: `high` if confidence=`high`, else `medium` | see INTERNAL-SCHEMA.md |
| (none) | — | `source` | hardcoded `nosey-parker` | always populated; enables per-source normalization in build.rs |
| (none) | — | `replacement_type` | derived from subcategory | see REPLACEMENT-TYPES.md for per-subcategory assignment table |

---

## Categories vs Tags: Critical Pitfall

This is the most dangerous field-mapping mistake when normalizing Nosey Parker rules. It must be read before writing any normalization code.

### What NP `categories` actually means

Nosey Parker's `categories` field contains capability flags that describe detection properties of the rule:

- `api` — pattern detects an API credential
- `identifier` — pattern detects an identifier (not necessarily secret on its own)
- `fuzzy` — pattern uses heuristic/context-anchored matching rather than a fixed prefix
- `secret` — pattern detects a secret value (the credential itself, not just an identifier)

These are detection metadata — they describe HOW the pattern matches, not WHAT type of sensitive data it is.

### What internal `category` means

The internal `category` field is the two-level taxonomy from Phase 1 decision D-09:

- `secret` — credentials, tokens, API keys, private keys
- `pii` — personally identifiable information (SSN, email, phone, CC number)
- `infra` — infrastructure identifiers (IP addresses, UUIDs)

This is a data classification taxonomy — it describes the TYPE of sensitive data detected.

### The mapping rule

```
NP categories  →  internal tags    (always)
internal category  ←  curated manifest  (always)
```

NP `categories` values (`api`, `identifier`, `fuzzy`, `secret`) become entries in the internal `tags` list.

Internal `category` is ALWAYS assigned from the curated manifest (`docs/analysis/CURATED-MANIFEST.md`), NEVER copied from NP `categories`.

### Concrete wrong example

**NP rule:**
```yaml
categories:
- api
- secret
```

**Wrong normalization:**
```yaml
# WRONG — do not do this
category: secret   # copied from NP categories — invalid
```

**Correct normalization:**
```yaml
# CORRECT
category: secret       # assigned from curated manifest (happens to agree here, but for the right reason)
tags: ["api", "secret"]  # NP categories preserved as tags
```

The fact that NP `categories` and internal `category` agree on the value `secret` in this case is coincidental. Consider a pattern that detects an AWS account ID — NP may label it `categories: [api, identifier]`, but the internal `category` might be `secret` (or `infra` depending on curation decisions). The values come from independent sources and must not be conflated.

---

## Multiline Pattern Handling

Nosey Parker frequently uses `(?x)` verbose mode for complex patterns that benefit from whitespace formatting and comments. This is important for build.rs normalization.

### What `(?x)` mode does

The `(?x)` flag (also called verbose or free-spacing mode) tells RE2 to:

1. Ignore unescaped whitespace inside the pattern (spaces, tabs, newlines)
2. Treat `#` through end-of-line as a comment

This allows patterns to be written across multiple lines with indentation and inline comments for readability. RE2 supports `(?x)` natively.

### How NP encodes multiline patterns in YAML

Multiline patterns use the YAML `|` block scalar (literal block style). The `|` preserves all newlines and leading whitespace exactly as written in the file:

```yaml
pattern: |
  (?x)(?i)
  \b
  aws_? (?:secret)? _? (?:access)? _? (?:key)?
  ["'']?
  \s{0,30}
  (?::|=>|=)
  \s{0,30}
  ["'']?
  ([a-z0-9/+=]{40})
  (?: [^a-z0-9/+=] | $ )
```

After YAML parsing, `serde_yml` produces this string (showing the embedded newlines):

```
(?x)(?i)\n\b\naws_? (?:secret)? _? (?:access)? _? (?:key)?\n["'']?\n\s{0,30}\n(?::|=>|=)\n\s{0,30}\n["'']?\n([a-z0-9/+=]{40})\n(?: [^a-z0-9/+=] | $ )\n
```

When RE2 compiles this string in `(?x)` mode, the newlines and spaces between tokens are ignored, and the pattern matches as if written on a single line. The result is identical to the compact single-line form.

### Rule for internal schema YAML

When copying a multiline NP pattern into `rules/patterns.yaml`:

- **Preserve as YAML block scalar** (`|`) — do NOT collapse to a single-quoted string
- **Do NOT add or remove leading spaces** — the indentation is significant to the YAML parser
- **Do NOT strip newlines** — they are part of the pattern string and `(?x)` mode handles them

Build.rs uses `serde_yml` which handles YAML block scalars natively. The resulting `regex: String` field in the Rust struct holds the full multiline string, which RE2 accepts.

### Concrete YAML representation

```yaml
# internal patterns.yaml — multiline pattern preserved correctly
- id: np.aws.2
  name: AWS Secret Access Key
  category: secret
  subcategory: aws
  source: nosey-parker
  regex: |
    (?x)(?i)
    \b
    aws_? (?:secret)? _? (?:access)? _? (?:key)?
    ["'']?
    \s{0,30}
    (?::|=>|=)
    \s{0,30}
    ["'']?
    ([a-z0-9/+=]{40})
    (?: [^a-z0-9/+=] | $ )
```

---

## Test Fixtures Handling

Nosey Parker's `examples` and `negative_examples` fields are build-time validation assets, not runtime schema fields.

### What they are

- `examples`: strings that MUST match the pattern (positive test cases)
- `negative_examples`: strings that MUST NOT match the pattern (negative test cases)

These allow build.rs to self-test every pattern during `cargo test` — catching regressions when patterns change.

### Why they are excluded from the runtime schema

At runtime, `rules/patterns.yaml` is compiled into the binary via `include_str!`. Loading test strings into the binary adds size with no detection benefit. Test fixtures are a development-time concern.

### Recommended preservation approach

Preserve `examples` and `negative_examples` in a companion file: `rules/patterns-test-fixtures.yaml`

This file is NOT loaded at runtime. Build.rs loads it during `cargo test` to run pattern self-tests.

**Suggested format for `rules/patterns-test-fixtures.yaml`:**

```yaml
fixtures:
  - id: np.aws.1
    examples:
      - 'A3T0ABCDEFGHIJKLMNOP'
      - 'AKIADEADBEEFDEADBEEF'
    negative_examples:
      - 'A3T0ABCDEFGHIJKLMNO'
      - 'A3T0ABCDEFGHIjklmnop'
      - '======================'

  - id: np.aws.2
    examples:
      - 'aws_secret_access_key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      - 'aws_secret_access_key => aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    negative_examples:
      - 'export AWS_SECRET_ACCESS_KEY=ded7db27a4558e2ea9bbf0bf36ae0e8521618f366c'
```

Build.rs test pseudocode:
```rust
// cargo test — load fixtures, compile pattern, assert matches
for fixture in fixtures {
    let rule = patterns.get(fixture.id);
    for example in fixture.examples {
        assert!(rule.regex.is_match(example), "pattern {} should match {:?}", fixture.id, example);
    }
    for neg in fixture.negative_examples {
        assert!(!rule.regex.is_match(neg), "pattern {} should NOT match {:?}", fixture.id, neg);
    }
}
```

This is a Phase 3/build.rs concern. The mapping document notes the recommended approach but does not specify the full implementation.

---

## Confidence Assignment Rules

Nosey Parker provides no explicit confidence field. Build.rs must infer confidence from pattern characteristics during normalization.

**Two-tier heuristic for NP rules:**

| Condition | Confidence | Rationale |
|-----------|------------|-----------|
| Pattern is prefix-anchored (starts with a known token prefix like `AKIA`, `ghp_`, `sk-ant-`) AND `categories` does not include `fuzzy` | `high` | Prefix-anchored patterns have very low false positive rates because the fixed token prefix is specific to one service |
| Pattern has `fuzzy` in `categories`, OR is a generic identifier pattern without a fixed prefix | `medium` | Fuzzy patterns rely on keyword context or generic character sets — higher FP risk than prefix-anchored forms |

Note: NP has no `low`-confidence patterns in the curated include set. Low-quality patterns are excluded at curation time (CURATED-MANIFEST.md). Build.rs does not need to emit `confidence: low` for any NP rule that passes the curation filter.

---

## Multi-file Structure Note

Nosey Parker rules are split across multiple YAML files organized by service area:

```
rules/vendor/nosey-parker/rules/
  aws.yml
  github.yml
  gitlab.yml
  slack.yml
  stripe.yml
  ... (more files)
```

Build.rs must enumerate ALL `*.yml` files in `rules/vendor/nosey-parker/rules/` — not just one file.

Use a glob pattern at compile time:

```rust
// build.rs — enumerate all NP rule files
let np_rules_dir = Path::new("rules/vendor/nosey-parker/rules");
for entry in fs::read_dir(np_rules_dir)? {
    let path = entry?.path();
    if path.extension().map(|e| e == "yml").unwrap_or(false) {
        // process this file
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
```

Failure to enumerate all files results in silently missing entire service categories (e.g., all GitHub patterns absent if `github.yml` is skipped).

---

## Before/After Normalization Example

Using the real `np.aws.2` (AWS Secret Access Key) rule from `rules/vendor/nosey-parker/rules/aws.yml`.

### Raw Nosey Parker Source (aws.yml)

```yaml
- name: AWS Secret Access Key
  id: np.aws.2

  pattern: |
    (?x)(?i)
    \b
    aws_? (?:secret)? _? (?:access)? _? (?:key)?
    ["'']?
    \s{0,30}
    (?::|=>|=)
    \s{0,30}
    ["'']?
    ([a-z0-9/+=]{40})
    (?: [^a-z0-9/+=] | $ )

  references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

  categories:
  - api
  - fuzzy
  - secret

  examples:
  - 'aws_secret_access_key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  - 'aws_secret_access_key => aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  - 'aws_access_key_id = FakeValues99ESPW3ALMEZ6U\n  aws_secret_access_key = FakeValues99cl9bqJFVA3iFUm+yqVe08HxhXFE/'

  negative_examples:
  - 'export AWS_SECRET_ACCESS_KEY=ded7db27a4558e2ea9bbf0bf36ae0e8521618f366c'
  - '"aws_secret_access_key" =  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaend'
```

### Normalized Internal Schema Output (rules/patterns.yaml)

```yaml
- id: np.aws.2                   # copied verbatim — already namespaced
  name: AWS Secret Access Key    # copied verbatim
  category: secret               # assigned from curated manifest (NOT from NP categories)
  subcategory: aws               # assigned from curated manifest
  source: nosey-parker           # hardcoded for this vendor
  confidence: medium             # fuzzy category present → medium (not high)
  regex: |                       # preserved as YAML block scalar — NOT flattened
    (?x)(?i)
    \b
    aws_? (?:secret)? _? (?:access)? _? (?:key)?
    ["'']?
    \s{0,30}
    (?::|=>|=)
    \s{0,30}
    ["'']?
    ([a-z0-9/+=]{40})
    (?: [^a-z0-9/+=] | $ )
  keywords: []                   # omitted from NP; no pre-filter applied
  entropy: null                  # NP has no entropy field; null = disabled
  tags:                          # NP categories copied here — NOT to category
    - api
    - fuzzy
    - secret
  checksum_type: null            # not a CC pattern; no checksum validation
  replacement_type: faker_api_key  # derived: secret/aws (secret key) → faker_api_key
  description: ""                # NP has no description field
  severity: medium               # derived from confidence: medium → severity medium
  # references: DROPPED — documentation URLs have no runtime use
  # examples: DROPPED — moved to rules/patterns-test-fixtures.yaml
  # negative_examples: DROPPED — moved to rules/patterns-test-fixtures.yaml
```

### Test Fixture Entry (rules/patterns-test-fixtures.yaml)

```yaml
- id: np.aws.2
  examples:
    - 'aws_secret_access_key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    - 'aws_secret_access_key => aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    - 'aws_access_key_id = FakeValues99ESPW3ALMEZ6U\n  aws_secret_access_key = FakeValues99cl9bqJFVA3iFUm+yqVe08HxhXFE/'
  negative_examples:
    - 'export AWS_SECRET_ACCESS_KEY=ded7db27a4558e2ea9bbf0bf36ae0e8521618f366c'
    - '"aws_secret_access_key" =  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaend'
```

The test fixtures retain the full original `examples` and `negative_examples` lists under the rule's `id`. Build.rs locates the fixture by matching `id` values between `rules/patterns.yaml` and `rules/patterns-test-fixtures.yaml`.

---

## Common Pitfalls

### Pitfall 1: Copying NP `categories` into internal `category`

**What goes wrong:** `categories: [api, fuzzy, secret]` → `category: secret` (wrong field, wrong source).

The internal `category` must come from the curated manifest (taxonomy: `secret/pii/infra`). NP `categories` are capability flags that belong in `tags`.

### Pitfall 2: Flattening multiline `(?x)` patterns into single-line strings

**What goes wrong:** A multiline `(?x)` pattern preserved as a YAML `|` block scalar is manually re-encoded as a single-quoted string. The embedded newlines and whitespace become literal characters in the pattern, breaking the `(?x)` mode assumptions and causing the pattern to never match.

Always preserve multiline patterns as YAML block scalars. Never collapse them into single-quoted or double-quoted strings.

### Pitfall 3: Processing only one NP YAML file

**What goes wrong:** Build.rs hardcodes `rules/vendor/nosey-parker/rules/aws.yml` instead of enumerating `*.yml`. This silently drops all patterns from `github.yml`, `gitlab.yml`, `slack.yml`, and all other service area files.

Always enumerate all `*.yml` files in the NP rules directory using a glob pattern or directory walk.
