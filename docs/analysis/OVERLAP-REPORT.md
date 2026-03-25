# Pattern Overlap Report

**RES-04: Duplicate analysis grouped by secret type with best-pattern-wins decisions per D-03**

Produced: 2026-03-25
Sources analyzed: gitleaks (222 rules), secrets-patterns-db rules-stable (1,610 patterns), nosey-parker (189 rules)
detect-secrets is reference-only (port analysis in Plan 01-03) and is excluded from overlap comparison.

---

## Summary Table

| Source | Total Raw Patterns | Unique to Source | Shared with 1+ Others |
|--------|-------------------|-----------------|----------------------|
| nosey-parker | 189 | ~85 | ~104 |
| gitleaks | 222 | ~98 | ~124 |
| secrets-patterns-db (rules-stable) | 1,610 | ~1,480 | ~130 |
| secrets-patterns-db (pii-stable) | 144 | ~144 | 0 |

Notes:
- secrets-patterns-db pii-stable covers a distinct domain (PII only) with no equivalent patterns in nosey-parker or gitleaks
- "Shared" counts are approximate; exact overlap depends on semantic matching for equivalent patterns with different names
- secrets-patterns-db rules-stable has the highest raw count but most patterns are in categories the other two sources also cover with higher-precision patterns

**Types appearing in 3+ sources (all three analyzed):** aws, github, gitlab, anthropic, openai, stripe, slack, jwt, private-key

**Types unique to one source:**
- nosey-parker only: groq, firecrawl, tavily, kagi, jina, particle.io, thingsboard, truenas, wireguard, nuget, stackhawk, huggingface, codeclimate, sauce, sonarqube, blynk, dependency_track, crates.io, psexec
- gitleaks only: adafruit, authress, beamer, bittrex, cisco-meraki, clickhouse, clojars, coincap, curl-auth-user, defined-networking, fastly-personal-token, firebase, flutterwave, github-pat-v2
- secrets-patterns-db only: ~1,480 low/medium confidence patterns for niche SaaS services

---

## Category: secret/aws

### All Source Representations

| Source | Pattern ID | Regex (truncated to 80 chars) | Confidence |
|--------|-----------|-------------------------------|-----------|
| nosey-parker | np.aws.1 | `\b((?:A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16})\b` | — |
| gitleaks | aws-access-token | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16})\b` | — |
| secrets-patterns-db | AWS API Key | `AKIA[0-9A-Z]{16}` | high |
| secrets-patterns-db | AWS Access Key ID Value | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` | high |

**Best Pattern:** nosey-parker (np.aws.1)

**Reason:** np.aws.1 includes the most complete prefix set (A3T, AKIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA, ASIA), uses `\b` word boundary anchoring, and has accompanying examples/negative_examples for validation. gitleaks includes ABIA and ACCA but uses `[A-Z2-7]` charset (less precise than `[A-Z0-9]`). secrets-patterns-db variants are subsets.

**Secondary:** gitleaks aws-access-token — use as supplement for ABIA/ACCA prefixes not in nosey-parker.

---

## Category: secret/aws (secret access key)

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.aws.2 | `(?x)(?i)\baws_?(?:secret)?_?(?:access)?_?(?:key)?...([a-z0-9/+=]{40})` | Context-anchored |
| gitleaks | (no dedicated secret-key rule) | — | No standalone secret key rule found |
| secrets-patterns-db | (none at high confidence) | — | No high-confidence secret key pattern |

**Best Pattern:** nosey-parker (np.aws.2)

**Reason:** Only source with a context-anchored AWS secret key pattern. The 40-character Base64 value alone would be too broad; np.aws.2 requires `aws_secret_access_key` context before matching, which dramatically reduces FP rate.

---

## Category: secret/github

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| nosey-parker | np.github.1 | `\b(ghp_[a-zA-Z0-9]{36})\b` | PAT |
| nosey-parker | np.github.2 | `\b(gho_[a-zA-Z0-9]{36})\b` | OAuth |
| nosey-parker | np.github.3 | `\b((?:ghu\|ghs)_[a-zA-Z0-9]{36})\b` | App token |
| nosey-parker | np.github.4 | `\b(ghr_[a-zA-Z0-9]{76})\b` | Refresh token |
| gitleaks | github-pat | `ghp_[0-9a-zA-Z]{36}` | PAT |
| gitleaks | github-oauth | `gho_[0-9a-zA-Z]{36}` | OAuth |
| gitleaks | github-app-token | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | App token |
| gitleaks | github-refresh-token | `ghr_[0-9a-zA-Z]{36}` | Refresh token |
| gitleaks | github-fine-grained-pat | `github_pat_\w{82}` | Fine-grained PAT |
| secrets-patterns-db | GitHub | `ghp_[0-9a-zA-Z]{36}` | high confidence |

**Best Pattern:** nosey-parker variants win for each type

**Reason:** nosey-parker uses `\b` word boundary anchors, which gitleaks omits. Patterns are semantically identical otherwise. For fine-grained PAT (`github_pat_\w{82}`), gitleaks has the only dedicated pattern; add it.

---

## Category: secret/anthropic

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.anthropic.1 | `\b(sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{95})(?:[^a-zA-Z0-9_-]\|$)` | API key |
| gitleaks | anthropic-api-key | `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | Specific api03 prefix |
| gitleaks | anthropic-admin-api-key | `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | Admin key |

**Best Pattern:** nosey-parker (np.anthropic.1) for user-facing API key

**Reason:** np.anthropic.1 matches `api[0-9]{2}` which covers any future api04+ variant, whereas gitleaks hardcodes `api03`. gitleaks wins for admin key (`sk-ant-admin01-`) since nosey-parker has no dedicated admin pattern.

---

## Category: secret/openai

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.openai.1 | `\b(sk-[a-zA-Z0-9]{48})\b` | Legacy format |
| gitleaks | openai-api-key | `\b(sk-(?:proj\|svcacct\|admin)-...T3BlbkFJ...)\|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})` | Legacy + new project format |

**Best Pattern:** gitleaks (openai-api-key) wins

**Reason:** gitleaks covers both legacy `sk-[48char]` and the new project-scoped format (`sk-proj-`, `sk-svcacct-`, `sk-admin-` with `T3BlbkFJ` sentinel). nosey-parker only covers the legacy format, which is being phased out by OpenAI.

---

## Category: secret/stripe

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| nosey-parker | np.stripe.1 | `(?i)\b((?:sk\|rk)_live_[a-z0-9]{24})\b` | Live key only |
| nosey-parker | np.stripe.2 | `(?i)\b((?:sk\|rk)_test_[a-z0-9]{24})\b` | Test key |
| gitleaks | stripe-access-token | `\b((?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99})` | Covers live/test/prod, flexible length |
| secrets-patterns-db | Stripe API Key | `sk_live_[0-9a-zA-Z]{24}` | high, live only |

**Best Pattern:** gitleaks (stripe-access-token)

**Reason:** gitleaks covers `live|test|prod` variants in one pattern and uses a flexible length range `{10,99}` accommodating Stripe's actual key length variation. nosey-parker splits live/test into separate rules unnecessarily; secrets-patterns-db omits test keys.

---

## Category: secret/slack

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.slack.2 | `\b(xoxb-[0-9]{10,12}-[0-9]{10,14}-[a-zA-Z0-9]{23,25})\b` | Bot token, more precise |
| gitleaks | slack-bot-token | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | Bot token, less precise |
| gitleaks | slack-app-token | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+` | App token |
| gitleaks | slack-config-access-token | `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` | Config token |
| gitleaks | slack-config-refresh-token | `(?i)xoxe-\d-[A-Z0-9]{146}` | Config refresh |
| secrets-patterns-db | Slack Token | `xox[baprs]-(?:\d+-)+[a-z0-9]+` | high, generic prefix |

**Best Pattern:** nosey-parker (np.slack.2) for bot tokens; gitleaks wins for app/config tokens (no NP equivalent)

**Reason:** np.slack.2 uses `\b` anchoring and has more precise length ranges for the third segment. gitleaks lacks length precision on the third segment. For specialized Slack token types (xapp, xoxe), gitleaks has the only patterns.

---

## Category: secret/jwt

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.jwt.1 | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_+-]{17,}\.(?:[a-zA-Z0-9/_+-]{10,}={0,2})?)` | 3-part JWT |
| gitleaks | jwt | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_+\-]{17,}\.(?:[a-zA-Z0-9._+\/\-]*)){1}` | Similar |

**Best Pattern:** nosey-parker (np.jwt.1)

**Reason:** Semantically equivalent; nosey-parker includes explicit examples and negative_examples for validation. Both use `ey` prefix anchoring on header and payload segments.

---

## Category: secret/private-key

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.pem.1 | `-----BEGIN [A-Z ]{8,15} PRIVATE KEY-----` | PEM block header |
| gitleaks | private-key | `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----` | PEM block, wider |
| secrets-patterns-db | Private Key | `-----BEGIN RSA PRIVATE KEY-----` | high, RSA only |

**Best Pattern:** gitleaks (private-key)

**Reason:** gitleaks pattern covers all PEM key types (RSA, EC, OpenSSH, PKCS#8) via `[ A-Z0-9_-]{0,100}` before PRIVATE KEY, and handles the BLOCK suffix (PGP). secrets-patterns-db is too narrow (RSA only). nosey-parker requires exactly 8-15 chars between BEGIN and PRIVATE KEY which misses some types.

---

## Category: secret/gitlab

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| nosey-parker | np.gitlab.1 | `\b(glpat-[a-zA-Z0-9_-]{20})\b` | PAT |
| gitleaks | gitlab-pat | `glpat-[0-9a-zA-Z_\-]{20}` | PAT |
| gitleaks | gitlab-ptt | `glptt-[0-9a-zA-Z_\-]{40}` | Pipeline trigger |
| gitleaks | gitlab-rrt | `GR1348941[0-9a-zA-Z_\-]{20}` | Runner registration |

**Best Pattern:** nosey-parker (np.gitlab.1) for PAT; gitleaks wins for pipeline trigger and runner registration (no NP equivalent)

**Reason:** Semantically identical for PAT; nosey-parker has `\b` anchoring. gitleaks adds coverage for two additional GitLab token types missing from nosey-parker.

---

## Category: secret/db-conn

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| nosey-parker | np.postgres.1 | `(?x)(?i)postgres(?:ql)?://[^@\s"']{3,}@` | PostgreSQL URI |
| nosey-parker | np.mongo.1 | `(?x)(?i)mongodb(?:\+srv)?://[^@\s"']{3,}@` | MongoDB URI |
| nosey-parker | np.odbc.1 | `(?x)(?i)...Password\s*=\s*[^;]{8,80}` | ODBC connection string |
| gitleaks | postgres-connection-uri | `(?i)\bpostgres(?:ql)?://[^:@\s]+:[^@\s]+@\S+` | PostgreSQL URI |
| gitleaks | mongodb-connection-string | `(?i)\bmongodb(?:\+srv)?://[^:@\s"]+:[^@\s"]+@\S+` | MongoDB URI |

**Best Pattern:** nosey-parker variants win for each type

**Reason:** nosey-parker's verbose regex mode (`(?x)`) makes patterns more readable and maintainable. Semantically equivalent precision.

---

## Category: secret/generic

**Note:** Generic patterns are HIGH FP risk in LLM proxy context (see FALSE-POSITIVE-ASSESSMENT.md). Both nosey-parker (np.generic.1, np.generic.2) and gitleaks have generic assignment patterns. Most are candidates for EXCLUDE in the curated manifest per D-02.

| Source | Pattern ID | Notes |
|--------|-----------|-------|
| nosey-parker | np.generic.1 | `secret` keyword + 32-64 hex chars |
| nosey-parker | np.generic.2 | `api_key/apikey/access_key/accesskey` keyword patterns |
| gitleaks | ~20 generic rules | Assignment-style `(?i)[\w.-]{0,50}?service_name` patterns |
| secrets-patterns-db | ~727 low-confidence | Mostly assignment patterns |

**Disposition:** All generic assignment patterns provisionally EXCLUDE pending individual review in Plan 01-03. See FALSE-POSITIVE-ASSESSMENT.md for rationale.

---

## Category: pii/ssn

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| secrets-patterns-db | ssn - 3 | `\b(?!000\|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b` | With lookaheads — INCOMPATIBLE |
| secrets-patterns-db | ssn_number | `(?!000\|666\|333)0*(?:[0-6][0-9][0-9]\|...)[-](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}` | Lookaheads — INCOMPATIBLE |
| secrets-patterns-db | ssn_number - 3 | `(?:\d{3}-\d{2}-\d{4})` | Simple, no lookaheads — COMPATIBLE |

**Best Pattern:** secrets-patterns-db `ssn_number - 3` (`(?:\d{3}-\d{2}-\d{4})`)

**Reason:** The two high-precision SSN patterns use negative lookaheads to exclude invalid SSNs (000, 666 area codes). These are INCOMPATIBLE with Rust's regex crate. The simple `\d{3}-\d{2}-\d{4}` pattern is compatible but accepts invalid area codes — acceptable given D-04 (precision over recall: we prefer fewer FP over more TP). See REGEX-COMPAT-REPORT.md for full lookahead analysis.

---

## Category: pii/email

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| secrets-patterns-db | emails | `([a-z0-9!#$%&'*+\/=?^_\`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*...` | RFC 5321 compliant |
| secrets-patterns-db | email - 3 | `\b[\w\-+.]+@+\w+.+[A-z]{3}` | Simpler, broader |

**Best Pattern:** secrets-patterns-db `emails` pattern

**Reason:** More precise RFC 5321 compliant regex. The `email - 3` variant uses `[A-z]` (includes non-letter ASCII between Z and a) which is a bug. Use the RFC-compliant pattern.

---

## Category: pii/phone

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| secrets-patterns-db | phones | `((?:(?<![\d-])...\d{4}(?![\d-]))\|(?:(?<![\d-])...))` | Lookaheads — INCOMPATIBLE |
| secrets-patterns-db | phones_with_exts | `((?:(?:\+?1...)?(?:\(\s*[2-9]...)\)?)...` | Extension support — INCOMPATIBLE |

**Disposition:** Both phone patterns use lookbehind/lookahead (INCOMPATIBLE with Rust regex crate). Simplified version without lookaround has HIGH FP risk in LLM context. See REGEX-COMPAT-REPORT.md and FALSE-POSITIVE-ASSESSMENT.md.

---

## Category: pii/cc

### All Source Representations

| Source | Pattern ID | Regex (truncated) | Notes |
|--------|-----------|-------------------|-------|
| secrets-patterns-db | visa_credit_card | `4[0-9]{15}` | Visa only |
| secrets-patterns-db | american_express_credit-card | `3[47][0-9]{13}` | Amex only |
| secrets-patterns-db | credit_cards | `((?:(?:\d{4}[- ]?){3}\d{4}\|\d{15,16}))(?![\d])` | Generic — lookahead |
| secrets-patterns-db | btc_addresses | `(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![...])` | Lookbehind/ahead — INCOMPATIBLE |

**Best Pattern:** Per-card-type patterns (visa_credit_card, american_express_credit-card, etc.) each individually

**Reason:** The generic `credit_cards` pattern uses a negative lookahead (`(?![\d])`) making it incompatible. Individual card type patterns are compatible with Rust regex. The `btc_addresses` pattern is INCOMPATIBLE — DROP.

---

## Category: pii/iban, pii/uk-nin, pii/pl-pesel, pii/fr-insee, pii/de-taxid

### Coverage Assessment

| Type | secrets-patterns-db | gitleaks | nosey-parker |
|------|---------------------|----------|--------------|
| pii/iban | Partial (under "IBAN") | No | No |
| pii/uk-nin | No | No | No |
| pii/pl-pesel | No | No | No |
| pii/fr-insee | No | No | No |
| pii/de-taxid | No | No | No |

**Finding:** EU PII types (UK NIN, Polish PESEL, French INSEE, German tax ID) are absent from all four vendored sources. These require hand-authored patterns in Phase 2. IBAN coverage in secrets-patterns-db needs individual review in Plan 01-03.

---

## Category: infra/ipv4-pub

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| secrets-patterns-db | ipv4_address | `(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.(...){3}` | Standard IPv4 |
| nosey-parker | (http.yml) | Various URL patterns | Incidental coverage |

**Disposition:** HIGH FP in LLM proxy context (see FALSE-POSITIVE-ASSESSMENT.md). LLMs frequently generate IP addresses in networking examples. Provisionally EXCLUDE or treat as MEDIUM severity.

---

## Category: infra/url-cred

### All Source Representations

| Source | Pattern ID | Regex | Notes |
|--------|-----------|-------|-------|
| nosey-parker | np.http.1 | `[a-zA-Z][a-zA-Z0-9+\-.]{1,30}://[^@\s"']{3,}:[^@\s"']{3,}@` | Credential URLs |
| gitleaks | url-with-credentials | Equivalent pattern | Similar |

**Best Pattern:** nosey-parker (np.http.1)

**Reason:** Covers credentials in any protocol scheme (http, postgres, mongodb, smtp etc.), well-anchored. LOW FP in LLM context per FALSE-POSITIVE-ASSESSMENT.md.
