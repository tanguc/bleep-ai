# Source Quality Assessment

**Per-source quality assessment with recommendations**

Produced: 2026-03-25

---

## nosey-parker

**Recommendation: PRIMARY for secrets**

### Precision

High. The nosey-parker project was designed by security engineers at Praetorian Security specifically for high precision in code scanning. Design philosophy explicitly prioritizes fewer FP over higher recall:
- 189 rules across 87 YAML files — narrowly scoped by service
- Prefix-anchored patterns are the dominant style (`ghp_`, `sk-ant-api03-`, `xoxb-`)
- Every pattern includes `examples` and `negative_examples` — built-in regression test cases
- `(?x)` verbose mode patterns are readable and reviewable
- Named categories (`fuzzy`, `generic`, `secret`) make FP-risk patterns identifiable

Approximate precision breakdown by rule count:
- ~150 rules: prefix-anchored (HIGH precision)
- ~25 rules: context-anchored (MEDIUM precision, e.g., `aws_secret_access_key` context)
- ~14 rules: generic/fuzzy (explicitly labeled, LOW precision, marked for individual review)

### Maintenance

Active. Last commit: 2026-02-21 (less than 2 months before vendoring date 2026-03-25). Repository is actively maintained by Praetorian Security. New rules added regularly for new token formats (groq, firecrawl, tavily visible in vendored files — these are recent AI service tokens).

Vendored commit: 2e6e7f36ce36619852532bbe698d8cb7a26d2da7 (2026-02-21)

### Format Ergonomics

Excellent. YAML format with:
- Distinct `name`, `id`, `pattern`, `categories`, `examples`, `negative_examples`, `references` fields
- `(?x)` verbose patterns with inline comments for complex regexes
- `categories` field maps directly to project taxonomy (api, secret, fuzzy, identifier)
- `references` links to upstream documentation for each service

The format is the most structured of all four sources — directly supports quality curation in Plan 01-03.

### Alignment with Project

Excellent fit for the LLM proxy use case:
- Security-engineer-curated by definition
- Explicit precision/recall tradeoff matches D-04
- Generic/fuzzy rules are explicitly labeled, making them easy to filter
- All patterns are fully Rust regex crate compatible (zero incompatible patterns found)
- `negative_examples` provide test cases for validation in Phase 2

### Recommendation

**PRIMARY for secrets.** Use nosey-parker as the authoritative source for all secrets patterns where it has coverage. When a type exists in both nosey-parker and gitleaks, nosey-parker wins by default (per overlap analysis in OVERLAP-REPORT.md). Supplement with gitleaks only for types not covered by nosey-parker or where gitleaks has additional token variants.

---

## gitleaks

**Recommendation: SUPPLEMENTARY for secrets**

### Precision

Moderate. Research cites ~46% overall precision from academic evaluation. However, this average masks a bimodal distribution:
- Prefix-anchored rules (e.g., `aws-access-token`, `github-*`, `stripe-*`): HIGH precision, similar to nosey-parker
- Generic assignment rules (e.g., `adafruit-api-key`, `adobe-client-id`, ~20+ SaaS-specific assignment patterns): LOW precision in LLM proxy context

Approximate breakdown of 222 rules:
- ~100 rules: prefix-anchored (HIGH precision) — these are the primary value
- ~80 rules: SaaS-specific assignment patterns using `(?i)[\w.-]{0,50}?service_name...` template — MEDIUM/LOW precision
- ~22 rules: allowlist rules (file extension allowlists in global config) — not detection rules
- ~20 rules: other (entropy-dependent, context-anchored)

### Maintenance

Very active. Last commit: 2026-03-25 (same day as vendoring). gitleaks is a widely used commercial-grade secret scanning tool with active community. 222 rules is the highest count of any source, reflecting ongoing community contributions.

Vendored commit: 8863af47d64c3681422523e36837957c74d4af4b (2026-03-25)

### Format Ergonomics

Good. TOML format with:
- `id`, `description`, `regex`, `entropy`, `keywords`, `[[rules.allowlists]]` fields
- `entropy` field is valuable for Phase 2 (high-entropy value → more likely real secret)
- `keywords` field maps to AhoCorasick pre-filter candidates (performance optimization for Phase 2)
- `secretGroup` identifies which capture group contains the actual secret value
- No examples/negative_examples — less testable than nosey-parker

The entropy and keywords metadata are the unique value-add over nosey-parker and make gitleaks worth including as supplementary even where patterns overlap.

### Alignment with Project

Good fit but requires aggressive curation. The generic assignment patterns are high-FP in LLM proxy context (see FALSE-POSITIVE-ASSESSMENT.md). The entropy metadata is not usable in Phase 1 but becomes valuable in Phase 2 when building the compiled pattern schema. The keywords are immediately useful as AhoCorasick pre-filter seeds.

All 222 rules are fully Rust regex crate compatible (zero incompatible patterns found — extensive `(?:...)` and `(?i)` usage is compatible).

### Recommendation

**SUPPLEMENTARY for secrets.** Use gitleaks for:
1. Types not covered by nosey-parker (e.g., fine-grained GitHub PAT `github_pat_\w{82}`, various less common SaaS services)
2. Additional token variants of types where nosey-parker exists (e.g., Stripe has both live and test patterns in gitleaks)
3. Entropy metadata — carry the entropy value into the schema even when nosey-parker wins the pattern

**Exclude** all generic assignment patterns from gitleaks (the `(?i)[\w.-]{0,50}?service_name` template with no prefix anchor in the service name's token value format).

---

## secrets-patterns-db

**Recommendation: PRIMARY for PII (pii-stable.yml), SUPPLEMENTARY for secrets after filtering (rules-stable.yml)**

### Precision

Highly variable and confidence-stratified. The source explicitly provides a `confidence` field:
- `rules-stable.yml`: 883 high-confidence, 727 low-confidence patterns (out of 1,610)
- `pii-stable.yml`: 144 patterns, all listed as high-confidence

The confidence field maps directly to FP risk. Low-confidence patterns are the primary contributor to the 1,600+ raw count but should not be included without individual review. Even high-confidence patterns vary significantly:
- Prefix-anchored high-confidence patterns: HIGH precision (equivalent to nosey-parker)
- Generic high-confidence patterns: MEDIUM precision
- Any low-confidence pattern: LOW precision, likely EXCLUDE in curation

**For PII (pii-stable.yml):** This is the only vendored source with structured PII patterns. Coverage includes phones, emails, SSN, credit cards, and some financial patterns. 6 patterns are incompatible with Rust regex crate (see REGEX-COMPAT-REPORT.md). After removing incompatible and out-of-scope patterns, the usable PII set is ~15-20 patterns.

### Maintenance

Moderate. Last commit: 2025-08-06 (~7 months before vendoring). Less actively maintained than nosey-parker and gitleaks. The 1,600+ pattern count suggests a different growth model (bulk import from various sources) rather than curated additions.

Vendored commit: 24984df1a3f78475132ed183cebce4452b601161 (2025-08-06)

### Format Ergonomics

Minimal. YAML with only three fields: `name`, `regex`, `confidence`. No examples, no negative_examples, no references, no category labels. The `confidence` field is the only metadata beyond the pattern itself.

This minimal format means curation is entirely manual — no built-in test cases, no references to upstream documentation, no category taxonomy. The confidence field is valuable but insufficient for automated quality filtering in isolation.

### Alignment with Project

Good for PII, mixed for secrets:
- **pii-stable.yml:** Only source covering US PII types (SSN, phone, CC, email). Direct alignment with D-06. Incompatible patterns have simplified alternatives. This file is the primary PII source by necessity.
- **rules-stable.yml:** The 883 high-confidence patterns cover many services but most overlap with nosey-parker and gitleaks at lower quality (no examples, no entropy, keyword context only). Primary value is as a secondary check: if nosey-parker and gitleaks both miss a service, rules-stable high-confidence patterns fill the gap.

6 patterns in pii-stable.yml use incompatible Rust regex features (all in PII patterns) — see REGEX-COMPAT-REPORT.md.

### Recommendation

**PRIMARY for PII (pii-stable.yml)** — the only structured PII source available. Include only patterns in the defined taxonomy (D-06 scope): phones, emails, SSN, CC, IBAN. Exclude out-of-scope patterns (street addresses, times, colors, bitcoin, MD5 hashes — all present in pii-stable.yml). Apply simplified versions of the 4 incompatible in-scope patterns.

**SUPPLEMENTARY for secrets (rules-stable.yml)** — use `confidence: high` only as a fill-in for types not covered by nosey-parker or gitleaks. Exclude `confidence: low` entirely.

---

## detect-secrets

**Recommendation: REFERENCE only — architecture reference and regex extraction for types not covered elsewhere**

### Precision

High for pure-regex detectors, but misleading if evaluated without the entropy component. detect-secrets was designed with the understanding that entropy filtering is part of the detection pipeline:
- `high_entropy_strings` detector: entirely entropy-based, no fixed regex
- `keyword` detector: keyword heuristic, not regex-based
- Most other detectors: regex + entropy threshold combination

Extracting the regex alone from a detector that relies on entropy for FP reduction produces a lower-precision pattern than the original detector intended. The academic precision evaluation of detect-secrets as a system incorporates entropy filtering; the patterns alone would score lower.

### Maintenance

Moderate. Last commit: 2025-01-06 (~15 months before vendoring). The project is maintained by Yelp and still accepts PRs but is not as actively developed as gitleaks or nosey-parker.

Vendored commit: 50119d658ab48021cad234fc5c8d3253263b2ec0 (2025-01-06)

### Format Ergonomics

Poor for the vendoring use case. Patterns are embedded in Python class methods (`DENYLIST`, `SECRET_TYPE`, `REGEX` class attributes) rather than standalone data files. Port analysis requires reading Python source code and extracting regex strings manually. No structured metadata — the entropy threshold and keyword list are hardcoded in each plugin class.

The Python-specific architecture (class inheritance, plugin registry, Python `re` module syntax) means the patterns are not directly portable — each detector requires individual analysis.

### Alignment with Project

Useful as reference only. Per D-11, a full port analysis (DETECT-SECRETS-PORT-ANALYSIS.md) will extract each of the 26 detectors' logic into a structured table. This analysis feeds Plan 01-03's inclusion/exclusion decisions for types that detect-secrets covers but nosey-parker and gitleaks don't.

Specific value areas:
- `artifactory_detector`: may cover Artifactory API keys not in nosey-parker (nosey-parker has artifactory.yml — verify)
- `azure_storage_key_detector`: Azure storage key detection
- `basic_auth_detector`: HTTP basic auth in URLs
- `cloudant_detector`: IBM Cloudant credentials
- Entropy-based detection logic: the Shannon entropy threshold values are useful reference data for Phase 2 schema

No Python code is executed. All patterns are extracted and reviewed as documentation only.

### Recommendation

**REFERENCE only.** Do not include detect-secrets patterns directly in the curated manifest without going through port analysis (Plan 01-03 / DETECT-SECRETS-PORT-ANALYSIS.md). The port analysis will identify which detectors have portable pure-regex patterns that can supplement nosey-parker and gitleaks.

---

## Coverage Gaps

The following taxonomy categories defined in D-06 and D-09 are **absent from all four vendored sources** and require hand-authored patterns in Phase 2:

| Category | Gap | Notes |
|----------|-----|-------|
| pii/uk-nin | No pattern in any source | UK National Insurance Number format: `XX-NN-NN-NN-X` or `XNNNNNNNX` |
| pii/pl-pesel | No pattern in any source | Polish PESEL: 11-digit format encoding birth date + sex + checksum |
| pii/fr-insee | No pattern in any source | French INSEE (NIR): 15-digit format with department, birth date, sex |
| pii/de-taxid | No pattern in any source | German Steueridentifikationsnummer: 11-digit non-hyphenated |
| pii/iban | Partial coverage only | secrets-patterns-db has IBAN patterns but coverage is incomplete; needs verification in Plan 01-03 |
| secret/bearer | Partial coverage | nosey-parker http.yml has authorization header patterns but bearer token generically is not specifically covered |

**Impact:** EU PII types (uk-nin, pl-pesel, fr-insee, de-taxid) must be hand-authored for Phase 2. These are required by D-06 (US + EU core PII scope) but are absent from all existing open-source pattern databases. Research on correct regex patterns for these formats is required before Phase 2 implementation. These are deferred out of the vendoring analysis phase and tracked as a Phase 2 prerequisite.

**IBAN note:** secrets-patterns-db pii-stable.yml contains IBAN patterns but their quality and coverage of all EU IBAN formats needs individual review in Plan 01-03. Do not assume full coverage until verified.

---

## Overall Recommendation Summary

| Source | Role | Use For | Exclude |
|--------|------|---------|---------|
| nosey-parker | PRIMARY secrets | All prefix-anchored service token patterns; use as default when overlap with gitleaks | Generic/fuzzy labeled patterns — review individually |
| gitleaks | SUPPLEMENTARY secrets | Token types not in nosey-parker; entropy/keywords metadata; fine-grained PAT | Generic assignment patterns (`[\w.-]{0,50}?service_name...` template) |
| secrets-patterns-db (pii-stable) | PRIMARY PII | In-scope PII types: phone, email, ssn, cc, iban | Out-of-scope: times, street addresses, colors, bitcoin, hashes, uk_phone (separate from uk-nin) |
| secrets-patterns-db (rules-stable) | SUPPLEMENTARY secrets | High-confidence fill-in for types not in nosey-parker/gitleaks | All low-confidence patterns; all patterns where nosey-parker/gitleaks already cover the type |
| detect-secrets | REFERENCE | Port analysis in Plan 01-03 to identify additional coverage | Direct inclusion — all patterns require individual review via port analysis |
