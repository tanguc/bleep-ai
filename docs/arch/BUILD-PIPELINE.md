# Rule Pipeline Spec

> **Note (April 2026):** The pipeline was originally implemented as `build.rs`
> but was refactored into `src/rule_pipeline.rs` + `src/bin/build-rules.rs`.
> See `docs/RULE-PIPELINE.md` for the current developer workflow. This document
> still describes the algorithmic spec, which is unchanged.

**Purpose:** Defines how the rule pipeline normalizes raw vendor pattern files into a single `rules/combined.yaml` that is embedded into the binary at compile time via `include_str!`. The pipeline is now an explicit binary you invoke when patterns change (`cargo run --bin build-rules`), not an automatic step on every `cargo build`.

---

## 1. Purpose and Scope

The pipeline (now `src/rule_pipeline.rs::run()`):
1. Reads raw vendor files (gitleaks TOML, secrets-patterns-db YAML, Nosey Parker YAML, hand-authored YAML)
2. Normalizes each into `Vec<NormalizedRule>` matching the schema in `docs/schema/INTERNAL-SCHEMA.md`
3. Deduplicates by `id`
4. Validates each rule (regex compilation, required fields, valid enum values)
5. Writes `rules/combined.yaml` (now committed to git, was previously gitignored)

`combined.yaml` is consumed by `include_str!("../../rules/combined.yaml")` in `src/patterns/mod.rs`, embedding the pattern library into the binary. No runtime file I/O.

---

## 2. Normalization Pipeline

### Step a: Parse Gitleaks TOML

Source: `rules/vendor/gitleaks/gitleaks.toml`

Use the `toml` crate as a build dependency. Parse the `[[rules]]` array. Each entry has:
- `id` — string
- `description` — string
- `regex` — string
- `entropy` — optional float
- `keywords` — optional string array
- `secretGroup` — optional int (capture group index)
- `tags` — optional string array
- `allowlists` — optional (ignored in normalization)

Apply curated include/exclude manifest: only process rules with ids listed as "included" in `docs/analysis/CURATED-MANIFEST.md` (or in `rules/EXCLUSIONS.yaml` — see section 8). Skip excluded ids.

Map to NormalizedRule:
- `id` → `gl.{id}` (prefix with `gl.`)
- `source` → `"gitleaks"`
- `name` → `description` field
- `confidence` → infer from entropy and pattern structure: prefix-anchored pattern = `high`, context-anchored = `medium`, generic = `low` (excluded at curation time)
- `entropy` → map float to `Option<f64>`; absent = `None`
- `keywords` → lowercase keyword array; absent = `[]`
- `replacement_type` → derive from category + subcategory lookup table (section 4)
- `category`, `subcategory` → derive from id/tags/description mapping

Log to stderr: count of rules parsed and count included after manifest filter.

---

### Step b: Parse secrets-patterns-db YAML

Sources: `rules/vendor/secrets-patterns-db/rules-stable.yml` and `pii-stable.yml`

Use `serde_yml` crate. Each entry in `rules-stable.yml` has:
- `name` — string
- `regex` — string
- `confidence` — `"high"` / `"medium"` / `"low"`

Each entry in `pii-stable.yml` has the same structure.

Apply curated manifest filter (same mechanism as gitleaks).

Map to NormalizedRule:
- `id` → `spdb.{slugify(name)}` where slugify lowercases and replaces spaces/special chars with `-`
- `source` → `"secrets-patterns-db"`
- `category` → `"secret"` for `rules-stable.yml`; `"pii"` for `pii-stable.yml`
- `subcategory` → derived from name patterns (e.g., name contains "AWS" → `aws`, "Email" → `email`)
- `confidence` → use field value directly
- `replacement_type` → derive from category + subcategory lookup table (section 4)

Attribution: add the following comment block at the top of `combined.yaml`:

```yaml
# This file contains patterns from:
# - secrets-patterns-db (CC-BY 4.0): https://github.com/mazen160/secrets-patterns-db
#   License: Creative Commons Attribution 4.0 (CC-BY 4.0)
#   Attribution: Mazin Ahmed / secrets-patterns-db contributors
#   See: rules/vendor/secrets-patterns-db/LICENSE
```

Note on id collision: if `spdb.{slugify(name)}` collides with an existing id (different name, same slug), append a numeric suffix: `spdb.{slug}-2`, `spdb.{slug}-3`, etc.

---

### Step c: Parse Nosey Parker YAML

Source: `rules/vendor/nosey-parker/rules/*.yml` (one or more YAML files per directory scan)

Parse each YAML file. Each file may contain multiple rules. Each rule has:
- `name` — string
- `pattern` — the regex string (not `regex`)
- `examples` — optional list of match examples
- `negative_examples` — optional list of non-match examples
- `categories` — optional string array (NP capability flags, NOT taxonomy)

Apply curated manifest filter.

Map to NormalizedRule:
- `id` → `np.{slugify(name)}`
- `source` → `"nosey-parker"`
- `confidence` → `"high"` (NP is the primary high-precision source; security-engineer-curated)
- `regex` → `pattern` field (NP calls it `pattern`)
- `categories` → map to `tags` (NOT to `category`) — NP categories are capability flags (`api`, `identifier`, `fuzzy`, etc.)
- `category`, `subcategory` → infer from rule name and content
- `replacement_type` → derive from category + subcategory lookup table (section 4)

Drop `examples` and `negative_examples` from the normalized schema. Preserve them separately in `rules/patterns-test-fixtures.yaml` for use in test suites (per Phase 2 schema decisions).

---

### Step d: Parse Hand-Authored Rules

Source: `rules/sensitive-patterns.yaml` (current bleep custom rules)

Fields in current schema: `id`, `name`, `category`, `severity`, `regex`, `description`.

These pass through with minimal transformation:
- `id` → prefix with `ha.` if not already prefixed
- `source` → `"hand-authored"`
- `tags` → add `["hand-authored"]` at minimum

Required hand-authored patterns (must be present — build fails if missing):
- `ha.pii.uk-nin`
- `ha.pii.pl-pesel`
- `ha.pii.fr-insee`
- `ha.pii.de-taxid`
- `ha.secret.ibm-cloud-iam`

---

### Step e: Merge and Deduplicate

Combine all four `Vec<NormalizedRule>` into one.

Deduplication rule: if two rules share the same `id`, keep the rule from the higher-priority source. Source priority (highest to lowest):

1. `hand-authored` (`ha.*`)
2. `nosey-parker` (`np.*`)
3. `gitleaks` (`gl.*`)
4. `secrets-patterns-db` (`spdb.*`)

Rationale: hand-authored rules are the most project-specific and have been manually validated. NP is the highest-precision automated source. gitleaks is well-maintained and widely adopted. secrets-patterns-db has the broadest coverage but lower per-rule precision.

Log to stderr: total rule count after dedup, count dropped per source.

---

### Step f: Validate Each Rule

For each rule in the merged set:

1. **Regex compilation:** `regex::bytes::Regex::new(&rule.regex)` — if this fails, emit build error:
   ```rust
   panic!("build.rs: invalid regex in rule {}: {}", rule.id, err)
   ```
2. **ID format:** assert `rule.id` is non-empty and contains no whitespace.
3. **Category:** assert `rule.category` is one of `secret | pii | infra`.
4. **Replacement type:** assert `rule.replacement_type` is one of the 16 defined values (list below).
5. **No duplicate IDs:** assert no two rules share the same `id` after dedup (defensive assert).
6. **Warnings (non-fatal):** log stderr warning if a `secret` or `pii` rule has `keywords: []` (no pre-filter) — this means the rule's regex runs on every body that passes the COMBINED pre-filter.

Valid `replacement_type` values (16 total):
`faker_email`, `faker_phone`, `faker_ssn`, `faker_cc_luhn`, `faker_iban`, `faker_uuid`, `faker_ipv4`, `faker_aws_key`, `faker_github_pat`, `faker_jwt`, `faker_api_key`, `faker_db_conn`, `faker_url_cred`, `fpe_numeric`, `generic_random`, `passthrough`

Log to stderr: total rules validated.

---

### Step g: Write combined.yaml

Output path: `rules/combined.yaml` (relative to `Cargo.toml`).

Format: YAML list serialized with `serde_yml`. Top-level structure:

```yaml
# Attribution block (see Step b above)
rules:
  - id: np.aws.1
    name: AWS API Key
    category: secret
    # ... all NormalizedRule fields
```

The file is gitignored (listed in `.gitignore`) — it is a build artifact and must not be committed.

**Rerun triggers** — add to `build.rs` output:

```rust
println!("cargo:rerun-if-changed=rules/sensitive-patterns.yaml");
println!("cargo:rerun-if-changed=rules/vendor/gitleaks/gitleaks.toml");
println!("cargo:rerun-if-changed=rules/vendor/secrets-patterns-db/rules-stable.yml");
println!("cargo:rerun-if-changed=rules/vendor/secrets-patterns-db/pii-stable.yml");
println!("cargo:rerun-if-changed=rules/vendor/nosey-parker/rules");
```

These triggers ensure cargo only rebuilds when pattern files change — not on every build.

---

## 3. Build Dependencies

Add to `Cargo.toml`:

```toml
[build-dependencies]
toml = "0.8"
serde_yml = "0.0"
serde = { version = "1", features = ["derive"] }
regex = "1"    # for validate step (separate compilation unit from [dependencies])
```

Note: `regex` is already in `[dependencies]`; it must also be listed in `[build-dependencies]` because `build.rs` is a separate compilation unit. They share the same version but build independently.

---

## 4. Replacement_type Derivation Table

Used by build.rs when a source rule has no explicit `replacement_type`. Implemented as a pure function: `derive_replacement_type(category: &str, subcategory: &str) -> &'static str`.

| Category | Subcategory | `replacement_type` |
|----------|-------------|-------------------|
| secret | aws (access key) | `faker_aws_key` |
| secret | aws (secret key) | `faker_api_key` |
| secret | github | `faker_github_pat` |
| secret | gitlab | `faker_api_key` |
| secret | stripe | `faker_api_key` |
| secret | sendgrid | `faker_api_key` |
| secret | slack | `faker_api_key` |
| secret | openai | `faker_api_key` |
| secret | anthropic | `faker_api_key` |
| secret | jwt | `faker_jwt` |
| secret | private-key | `faker_api_key` |
| secret | db-conn | `faker_db_conn` |
| secret | url-cred | `faker_url_cred` |
| secret | npm | `faker_api_key` |
| secret | pypi | `faker_api_key` |
| secret | telegram | `faker_api_key` |
| secret | generic | `faker_api_key` |
| pii | email | `faker_email` |
| pii | phone | `faker_phone` |
| pii | ssn | `faker_ssn` |
| pii | cc | `faker_cc_luhn` |
| pii | iban | `faker_iban` |
| pii | uk-nin | `generic_random` |
| pii | pl-pesel | `generic_random` |
| pii | fr-insee | `generic_random` |
| pii | de-taxid | `generic_random` |
| pii | address | `generic_random` |
| infra | ipv4 | `passthrough` |
| infra | uuid | `faker_uuid` |
| infra | url-cred | `faker_url_cred` |
| (no match) | — | `generic_random` |

---

## 5. Error Handling Policy

| Error | Action | Rationale |
|-------|--------|-----------|
| Invalid regex | `panic!` — fails the build | Developer must fix the rule before shipping; no runtime surprises |
| Missing vendor file | `panic!` — fails the build | Developer must run Phase 1 vendoring first |
| Malformed TOML | `panic!` — fails the build | Upstream format changed; developer must adapt the parser |
| Malformed YAML | `panic!` — fails the build | Same as above |
| Invalid `replacement_type` value | `panic!` — fails the build | Schema mismatch; developer must fix normalization logic |
| Empty rule set after dedup | `panic!` — fails the build | Something went badly wrong in normalization |

Build.rs panics are compile-time failures. They are preferable to runtime surprises in production. A `cargo build` that fails with a clear error message is better than a binary that silently passes secrets through.

---

## 6. combined.yaml Format

```yaml
# This file is generated by build.rs. DO NOT EDIT MANUALLY.
# See rules/vendor/ for upstream sources.
#
# Attribution:
# - secrets-patterns-db (CC-BY 4.0): https://github.com/mazen160/secrets-patterns-db
#   See rules/vendor/secrets-patterns-db/LICENSE
rules:
  - id: np.aws.1
    name: "AWS API Key"
    category: secret
    subcategory: aws
    source: nosey-parker
    confidence: high
    regex: '\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b'
    keywords: ["akia", "asia", "agpa"]
    entropy: null
    tags: ["api", "identifier", "prefix-anchored"]
    checksum_type: null
    replacement_type: faker_aws_key
    description: "AWS IAM access key ID"
    severity: high
```

The file is listed in `.gitignore` since it is a build artifact. It is regenerated on every `cargo build` when vendor files change.

`include_str!("../rules/combined.yaml")` in `src/patterns/mod.rs` embeds it at compile time.

---

## 7. Runtime Pattern Loading

`src/patterns/mod.rs` owns the compiled statics:

```rust
static NORMALIZED_RULES: LazyLock<Vec<NormalizedRule>> =
    LazyLock::new(|| serde_yml::from_str(include_str!("../rules/combined.yaml"))
        .expect("combined.yaml embedded at build time must be valid YAML"));

static COMBINED: LazyLock<AhoCorasick> =
    LazyLock::new(|| {
        let keywords: Vec<&str> = NORMALIZED_RULES.iter()
            .flat_map(|r| r.keywords.iter().map(|k| k.as_str()))
            .collect();
        AhoCorasick::new(keywords).expect("AhoCorasick build failed")
    });

static RULES: LazyLock<Vec<(Arc<NormalizedRule>, Regex)>> =
    LazyLock::new(|| {
        NORMALIZED_RULES.iter()
            .map(|r| {
                let re = regex::bytes::Regex::new(&r.regex)
                    .expect("regex pre-validated by build.rs");
                (Arc::new(r.clone()), re)
            })
            .collect()
    });
```

First access compiles all regexes. Expected startup overhead: ~50–200ms for 500 rules (acceptable; one-time cost on first request).

---

## 8. Curated Manifest Integration

`docs/analysis/CURATED-MANIFEST.md` is the human-readable source of truth for which upstream ids are included. However, having `build.rs` parse Markdown is fragile.

**Recommended approach:** Maintain `rules/EXCLUSIONS.yaml` — a machine-readable YAML file listing upstream ids to exclude:

```yaml
# rules/EXCLUSIONS.yaml
# IDs to exclude from normalization. Rationale is in docs/analysis/CURATED-MANIFEST.md.
excluded:
  - gitlab_token          # covers (?!\w) negative lookahead; not RE2-compatible
  - ip_public             # high FP in LLM context
  # ... etc.
```

`build.rs` reads this file at build time (`rerun-if-changed=rules/EXCLUSIONS.yaml`) and skips any upstream id present in the `excluded` list. This keeps the exclusion list machine-readable without parsing markdown.

Add the trigger:
```rust
println!("cargo:rerun-if-changed=rules/EXCLUSIONS.yaml");
```

---

## Links

- NormalizedRule schema — see `docs/schema/INTERNAL-SCHEMA.md`
- Replacement type enum and derivation rules — see `docs/schema/REPLACEMENT-TYPES.md`
- Curated pattern manifest — see `docs/analysis/CURATED-MANIFEST.md`
- Runtime consumers — see `docs/arch/DETECTION-PIPELINE.md` (COMBINED, RULES statics)
