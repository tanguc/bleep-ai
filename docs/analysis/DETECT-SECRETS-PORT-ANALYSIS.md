# detect-secrets Port Analysis

**Source:** rules/vendor/detect-secrets/plugins/
**Version:** 50119d658ab48021cad234fc5c8d3253263b2ec0 (2025-01-06)
**Plugin count:** 26

## Summary

| Portability | Count | Plugins |
|-------------|-------|---------|
| HIGH | 21 | artifactory, aws, azure_storage_key, basic_auth, discord, github_token, jwt, mailchimp, npm, openai, private_key, pypi_token, sendgrid, slack, square_oauth, stripe, telegram_token, twilio, ibm_cos_hmac, softlayer, cloudant |
| MEDIUM | 2 | high_entropy_strings, keyword |
| LOW | 1 | ibm_cloud_iam |
| EXCLUDE | 2 | ip_public, gitlab_token |

Note: gitlab_token is EXCLUDE not because it is unportable, but because it uses `(?!\w)` negative lookahead, which is incompatible with Rust's regex crate, and the patterns are fully covered by better-anchored equivalents in nosey-parker and gitleaks.

---

## Plugin Analysis

### artifactory

| Field | Value |
|-------|-------|
| Regex | `(?:\s\|=\|:\|"\|^)AKC[a-zA-Z0-9]{10,}(?:\s\|"\|$)` (API token); `(?:\s\|=\|:\|"\|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s\|"\|$)` (password) |
| Entropy | none |
| Keywords | none (context anchored by surrounding delimiters) |
| Other | two patterns: one for API tokens (AKC prefix), one for encrypted passwords (AP[A-F0-9] prefix) |
| Portability | HIGH |
| Port Notes | Rust regex crate equivalent: `(?:[\s=:"]|^)AKC[a-zA-Z0-9]{10,}(?:[\s"]|$)` and `(?:[\s=:"]|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:[\s"]|$)`. The `^` in character class inside `(?:...)` is a literal in Python re but needs care in Rust — use `(?m)` mode or anchor differently. Preferred: use nosey-parker artifactory.yml which has cleaner `AKC[a-zA-Z0-9]{10,}` and `AP[A-Z][a-zA-Z0-9]{8,}` anchored by `\b`. |

---

### aws

| Field | Value |
|-------|-------|
| Regex | `(?:A3T[A-Z0-9]\|ABIA\|ACCA\|AKIA\|ASIA)[0-9A-Z]{16}` (access key ID); `aws.{0,20}?(?:key\|pwd\|pw\|password\|pass\|token).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]` (secret key) |
| Entropy | none for access key ID; implicit (40-char base64 value) for secret key |
| Keywords | `aws` in the context for secret key; `key\|pwd\|pw\|password\|pass\|token` keyword |
| Other | optional HTTP verification via STS GetCallerIdentity API (Python-specific verify() method — not ported) |
| Portability | HIGH |
| Port Notes | Access key ID Rust regex: `\b(?:A3T[A-Z0-9]\|ABIA\|ACCA\|AKIA\|ASIA)[0-9A-Z]{16}\b`. Secret key Rust regex: `(?i)aws.{0,20}?(?:key\|pwd\|pw\|password\|pass\|token).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]`. The ABIA and ACCA prefixes are present in detect-secrets but absent from nosey-parker; add them to the curated pattern. HTTP verification is Python-only and not ported. |

---

### azure_storage_key

| Field | Value |
|-------|-------|
| Regex | `AccountKey=[a-zA-Z0-9+\/=]{88}` |
| Entropy | none (length 88 acts as implicit entropy signal) |
| Keywords | `AccountKey` is the key anchor |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `AccountKey=[a-zA-Z0-9+/=]{88}`. The `\/` in Python is just `/` — no change needed. This covers Azure Blob Storage connection strings. Note: prior research suggested LOW for azure_storage_key; actual plugin code is pure regex with no URL parsing — corrected to HIGH. |

---

### basic_auth

| Field | Value |
|-------|-------|
| Regex | `://[^:/?#\[\]@!$&'()*+,;=\s]+:([^:/?#\[\]@!$&'()*+,;=\s]+)@` |
| Entropy | none |
| Keywords | `://` scheme indicator |
| Other | excludes RFC 3986 reserved characters from username/password segments |
| Portability | HIGH |
| Port Notes | Rust regex: `://[^:/?#\[\]@!$&'()*+,;={}\s]+:([^:/?#\[\]@!$&'()*+,;={}\s]+)@`. The character class is slightly simpler in Rust as `{}` doesn't need escaping inside `[...]`. Equivalent to nosey-parker np.http.1 for credential-in-URL detection. |

---

### cloudant

| Field | Value |
|-------|-------|
| Regex (primary) | Context-anchored assignment: `(?i)(?:cloudant\|cl\|clou)(?:api\|)(?:key\|pwd\|pw\|password\|pass\|token)\s*(?:=\|:=\|=>)\s*['"]?([0-9a-f]{64}\|[a-z]{24})['"]?` |
| Regex (URL form) | `(?i)https?://[\w-]+:([0-9a-f]{64}\|[a-z]{24})@[\w-]+\.cloudant\.com` |
| Entropy | none |
| Keywords | `cloudant`, `cl`, `clou` prefix; `key`, `pwd`, `password`, `pass`, `token` suffix |
| Other | optional HTTP verification against cloudant.com endpoint |
| Portability | HIGH |
| Port Notes | The `build_assignment_regex` helper generates a standard keyword-assignment pattern. Rust equivalent for URL form: `(?i)https?://[\w-]+:([0-9a-f]{64}\|[a-z]{24})@[\w-]+\.cloudant\.com`. Assignment form requires keyword context scanning — implement as two passes or use the URL form as primary. HTTP verification is Python-only. |

---

### discord

| Field | Value |
|-------|-------|
| Regex | `[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}` |
| Entropy | none |
| Keywords | none (prefix `[MNO]` is the anchor) |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}`. Replace `\d` with `[0-9]` (equivalent in Rust regex). The three-segment structure with specific length ranges is distinctive. |

---

### github_token

| Field | Value |
|-------|-------|
| Regex | `(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9_]{36}` |
| Entropy | none |
| Keywords | none (prefix is the anchor) |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `(?:ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9_]{36}`. Consolidates 5 token types into one pattern. nosey-parker has separate rules per token type (np.github.1 through np.github.4) with `\b` anchoring and slightly different length specs — prefer nosey-parker variants as PRIMARY. |

---

### gitlab_token

| Field | Value |
|-------|-------|
| Regex | Multiple: `(glpat\|gldt\|glft\|glsoat\|glrt)-[A-Za-z0-9_-]{20,50}(?!\w)` (personal/deploy/feed/OAuth/runner); `GR1348941[A-Za-z0-9_-]{20,50}(?!\w)` (runner registration); `glcbt-([0-9a-fA-F]{2}_)?[A-Za-z0-9_-]{20,50}(?!\w)` (CI/CD); `glimt-[A-Za-z0-9_-]{25}(?!\w)` (incoming mail); `glptt-[A-Za-z0-9_-]{40}(?!\w)` (trigger); `glagent-[A-Za-z0-9_-]{50,1024}(?!\w)` (agent); `gloas-[A-Za-z0-9_-]{64}(?!\w)` (OAuth app secret) |
| Entropy | none |
| Keywords | none (prefix is the anchor) |
| Other | uses `(?!\w)` negative lookahead — INCOMPATIBLE with Rust regex crate |
| Portability | EXCLUDE |
| Port Notes | The `(?!\w)` suffix on all patterns is incompatible with Rust's regex crate. Simplified versions dropping `(?!\w)` are viable but gitleaks already covers glpat, glptt, and GR1348941 without lookahead, and nosey-parker covers glpat with `\b` anchoring. The additional token types (glcbt, glimt, glagent, gloas) from detect-secrets are newer GitLab formats — add to supplementary coverage list for Phase 2 hand-authoring without the lookahead. |

---

### high_entropy_strings

| Field | Value |
|-------|-------|
| Regex | `(['"]) ([charset]+) (\1)` — finds quoted strings matching the charset |
| Entropy | Shannon entropy calculation; two subclasses: Base64 threshold=4.5, Hex threshold=3.0 |
| Keywords | none (value-only detection via entropy) |
| Other | Two concrete subclasses: `Base64HighEntropyString` (charset: `[A-Za-z0-9+/\\-_=]`, limit=4.5) and `HexHighEntropyString` (charset: `[0-9a-fA-F]`, limit=3.0). Hex subclass applies extra penalty for all-numeric strings: `entropy -= 1.2 / log2(len(data))`. Requires quoted string context. |
| Portability | MEDIUM |
| Port Notes | Shannon entropy formula is straightforward to implement in Rust: `H = -sum(p * log2(p))` for each charset character. Phase 2 must implement: (1) quoted string extraction regex, (2) charset filtering, (3) Shannon entropy calculation, (4) threshold comparison. The all-numeric penalty for Hex entropy is: subtract `1.2 / log2(len)` when input parses as integer. These thresholds (Base64=4.5, Hex=3.0) should be configurable in the Phase 2 schema. |

---

### ibm_cloud_iam

| Field | Value |
|-------|-------|
| Regex | Assignment pattern: keyword context (`ibm_cloud_iam`, `cloud_iam`, `ibm_cloud`, etc.) + `(?:key\|pwd\|password\|pass\|token)` + `([a-zA-Z0-9_-]{44}(?![a-zA-Z0-9_-]))` |
| Entropy | none |
| Keywords | `ibm`, `iam`, `cloud` prefix variants |
| Other | uses `(?![a-zA-Z0-9_-])` negative lookahead in value regex — INCOMPATIBLE with Rust regex crate; optional HTTP verification against `iam.cloud.ibm.com` |
| Portability | LOW |
| Port Notes | The `(?![a-zA-Z0-9_-])` after the 44-char value is incompatible. Simplified: `[a-zA-Z0-9_-]{44}` — will match the value but may also match longer values truncated at 44 chars. The keyword assignment context (`build_assignment_regex`) also uses Python regex helpers that need manual translation. The 44-char value has no distinctive prefix, relying entirely on keyword context — HIGH FP risk without the lookahead precision. Classify as LOW portability due to incompatible lookahead and poor prefix anchoring. Not covered by nosey-parker or gitleaks; hand-author in Phase 2 with `\b` word boundary as lookahead substitute. |

---

### ibm_cos_hmac

| Field | Value |
|-------|-------|
| Regex | Assignment pattern: `(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?\|)` prefix + `(?:secret[-_]?(?:access)?[-_]?key)` keyword + `([a-f0-9]{48}(?![a-f0-9]))` value |
| Entropy | none |
| Keywords | `cos`, `hmac`, `secret`, `access`, `key` |
| Other | uses `(?![a-f0-9])` negative lookahead — INCOMPATIBLE; HTTP verification against IBM COS S3 API |
| Portability | HIGH |
| Port Notes | The `(?![a-f0-9])` suffix is the only incompatible element. Simplified value regex: `[a-f0-9]{48}`. Word boundary `\b` after a hex string works as an equivalent since hex chars are word chars. Full pattern: `(?i)(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)(?:secret[-_]?(?:access)?[-_]?key)\s*(?:=\|:=\|=>)\s*['"]?([a-f0-9]{48})\b`. Classified HIGH because the port is straightforward — just drop the lookahead and use `\b`. |

---

### ip_public

| Field | Value |
|-------|-------|
| Regex | Complex: negative lookbehind `(?<![\w.])` + negative lookahead `(?!192\.168\.\|127\.\|10\.\|169\.254\.\|172\.(?:1[6-9]\|2[0-9]\|3[01]))` + IPv4 octet pattern + optional port + negative lookahead `(?![\w.])` |
| Entropy | none |
| Keywords | none |
| Other | both lookbehind and negative lookahead — fully INCOMPATIBLE with Rust regex crate; the exclusion of private IP ranges cannot be replicated without lookaround |
| Portability | EXCLUDE |
| Port Notes | EXCLUDE in curated manifest. Reason: (1) pattern uses multiple incompatible lookaround constructs, (2) HIGH FP rate in LLM proxy context — LLMs generate public IP addresses constantly in networking tutorials, server configuration examples, and security research discussions. Even with private IP exclusion working, the FP rate is unacceptable as a blocking rule. See FALSE-POSITIVE-ASSESSMENT.md for full rationale. |

---

### jwt

| Field | Value |
|-------|-------|
| Regex | `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*?` |
| Entropy | none |
| Keywords | `eyJ` base64-encoded `{"` header anchor |
| Other | Python-side validation: decodes header and payload as base64+JSON, validates padding. Not a regex operation — Python-specific post-match filter. |
| Portability | HIGH |
| Port Notes | Rust regex: `eyJ[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*(?:\.[A-Za-z0-9_+/=-]*)?`. The regex alone is portable; the JSON validity check is optional enhancement for Phase 2. The `eyJ` anchor is distinctive (base64 encoding of `{"`) making pure regex detection sufficient for initial implementation. nosey-parker np.jwt.1 is slightly more precise — use as PRIMARY. |

---

### keyword

| Field | Value |
|-------|-------|
| Regex | Generated from DENYLIST of keyword stems: `api_?key`, `auth_?key`, `service_?key`, `account_?key`, `db_?key`, `database_?key`, `priv_?key`, `private_?key`, `client_?key`, `db_?pass`, `database_?pass`, `key_?pass`, `password`, `passwd`, `pwd`, `secret`, `contraseña`, `contrasena` |
| Entropy | none (keyword proximity is the signal) |
| Keywords | the entire DENYLIST — see above |
| Other | complex logic: identifies secret as value following keyword assignment (`=`, `:=`, `=>`, `:`, `==`), in various code formats (YAML, env files, Python, JS). Handles quoted/unquoted values, bracket notation, string comparison. |
| Portability | MEDIUM |
| Port Notes | The keyword list itself is portable. The complex assignment-pattern detection (`FOLLOWED_BY_COLON_EQUAL_SIGNS_REGEX`, `FOLLOWED_BY_COLON_REGEX`, `FOLLOWED_BY_EQUAL_SIGNS_REGEX`, etc.) requires Rust implementation of multiple patterns. Phase 2 can implement as an AhoCorasick pre-filter on keyword stems + regex confirmation of assignment context. The `contraseña`/`contrasena` entries require Unicode support (`\w` matching Spanish chars) — Rust regex crate supports Unicode by default. HIGH FP risk: generic keyword patterns without prefix anchoring fire on any configuration discussion. Classify as MEDIUM: keyword list is portable but the detection logic requires significant Rust implementation work. |

---

### mailchimp

| Field | Value |
|-------|-------|
| Regex | `[0-9a-z]{32}-us[0-9]{1,2}` |
| Entropy | none |
| Keywords | `-us` suffix with datacenter number is the distinguishing anchor |
| Other | HTTP verification against mailchimp.com API |
| Portability | HIGH |
| Port Notes | Rust regex: `[0-9a-z]{32}-us[0-9]{1,2}`. The `-us{N}` suffix makes this distinctive enough. Note: this pattern is not anchored — a 32-char lowercase+digit prefix can match many values. The `-us\d{1,2}` suffix is the real precision anchor. Add `\b` prefix: `\b[0-9a-z]{32}-us[0-9]{1,2}\b`. |

---

### npm

| Field | Value |
|-------|-------|
| Regex | `//.+/:_authToken=\s*((npm_.+)\|([A-Fa-f0-9-]{36})).*` |
| Entropy | none |
| Keywords | `_authToken=` is the anchor |
| Other | none — pure regex; designed for .npmrc file format |
| Portability | HIGH |
| Port Notes | Rust regex: `//.+/:_authToken=\s*(?:(npm_[^\s]+)\|([A-Fa-f0-9-]{36}))`. Two forms: legacy UUID form (`[A-Fa-f0-9-]{36}`) and new `npm_` prefixed form. The `.npmrc` format `//registry.npmjs.org/:_authToken=` is the context. In Rust use `[^\s]+` instead of `.+` for the npm_ value to avoid runaway matches. |

---

### openai

| Field | Value |
|-------|-------|
| Regex | `sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}` |
| Entropy | none |
| Keywords | `sk-` prefix; `T3BlbkFJ` sentinel (base64 of `openai`) |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `sk-[A-Za-z0-9_-]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`. The `T3BlbkFJ` sentinel is a unique fingerprint. Note: gitleaks openai-api-key also covers `sk-proj-`, `sk-svcacct-`, `sk-admin-` new format and is the PREFERRED pattern (wider coverage). detect-secrets only covers the legacy format with sentinel. |

---

### private_key

| Field | Value |
|-------|-------|
| Regex | 8 separate patterns: `BEGIN DSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN PGP PRIVATE KEY BLOCK`, `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN SSH2 ENCRYPTED PRIVATE KEY`, `PuTTY-User-Key-File-2` |
| Entropy | none |
| Keywords | `PRIVATE KEY` or `PuTTY-User-Key-File-2` |
| Other | none — pure string matching (each pattern is a literal) |
| Portability | HIGH |
| Port Notes | All 8 literals are directly portable. Rust regex: use alternation `BEGIN (?:DSA\|EC\|OPENSSH\|PGP\|RSA\|SSH2 ENCRYPTED) PRIVATE KEY(?:\s+BLOCK)?` or match the PEM header pattern `-----BEGIN [A-Z ]+ PRIVATE KEY[^-]*-----`. gitleaks private-key pattern is more general and preferred as PRIMARY; detect-secrets patterns are additive for PuTTY and SSH2 Encrypted forms. |

---

### pypi_token

| Field | Value |
|-------|-------|
| Regex | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}` (production); `pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}` (test) |
| Entropy | none |
| Keywords | `pypi-AgEI` / `pypi-AgEN` are base64-encoded host prefixes — highly distinctive |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{70,}` and `pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9_-]{70,}`. The `pypi-AgEI` prefix is base64 of `\x01\x02\x08pypi.org` — unique to PyPI tokens. Both production and test.pypi.org forms should be included. |

---

### sendgrid

| Field | Value |
|-------|-------|
| Regex | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` |
| Entropy | none |
| Keywords | `SG.` prefix is the anchor |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`. The three-segment structure `SG.{22}.{43}` is highly distinctive. Add `\b` prefix to prevent matching `MSG.` etc.: `\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`. |

---

### slack

| Field | Value |
|-------|-------|
| Regex | `xox(?:a\|b\|p\|o\|s\|r)-(?:\d+-)+[a-z0-9]+` (tokens); `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+` (webhooks) |
| Entropy | none |
| Keywords | `xox` prefix for tokens; `hooks.slack.com` for webhooks |
| Other | HTTP verification for both forms (Python-specific) |
| Portability | HIGH |
| Port Notes | Token Rust regex: `xox(?:a\|b\|p\|o\|s\|r)-(?:\d+-)+[a-z0-9]+`. Webhook Rust regex: `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`. nosey-parker np.slack.2 is preferred for bot tokens (more precise length ranges); gitleaks covers app tokens and config tokens. detect-secrets adds webhook URL detection which is unique — use as supplementary. |

---

### softlayer

| Field | Value |
|-------|-------|
| Regex | Assignment: `(?:softlayer\|sl)(?:_\|-\|)(?:api\|)(?:key\|pwd\|password\|pass\|token)\s*(?:=\|:=\|=>)\s*['"]?([a-z0-9]{64})['"]?`; URL form: `(?:http\|https)://api.softlayer.com/soap/(?:v3\|v3.1)/([a-z0-9]{64})` |
| Entropy | none |
| Keywords | `softlayer`, `sl` prefix; `api.softlayer.com` in URL form |
| Other | HTTP verification via SoftLayer API |
| Portability | HIGH |
| Port Notes | URL form Rust regex: `(?i)https?://api\.softlayer\.com/soap/v3(?:\.1)?/([a-z0-9]{64})`. The URL form is more distinctive and less FP-prone than the assignment form. Assignment form is a generic keyword pattern — MEDIUM precision. Use URL form as PRIMARY; assignment form requires keyword context scanning. |

---

### square_oauth

| Field | Value |
|-------|-------|
| Regex | `sq0csp-[0-9A-Za-z\\-_]{43}` |
| Entropy | none |
| Keywords | `sq0csp-` prefix |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `sq0csp-[0-9A-Za-z_-]{43}`. The `\\-` in the Python source is `\-` (literal hyphen) in the character class — equivalent to `-` when at start/end. Rust: `sq0csp-[0-9A-Za-z_-]{43}`. The `sq0csp-` prefix is distinctive. |

---

### stripe

| Field | Value |
|-------|-------|
| Regex | `(?:r\|s)k_live_[0-9a-zA-Z]{24}` |
| Entropy | none |
| Keywords | `sk_live_` / `rk_live_` prefix |
| Other | HTTP verification against Stripe charges API |
| Portability | HIGH |
| Port Notes | Rust regex: `(?:r\|s)k_live_[0-9a-zA-Z]{24}`. detect-secrets only covers `_live_` variants, missing `_test_` and `_prod_`. gitleaks stripe-access-token covers all variants `(?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99}` and is the PREFERRED pattern. detect-secrets is a strict subset. |

---

### telegram_token

| Field | Value |
|-------|-------|
| Regex | `^\d{8,10}:[0-9A-Za-z_-]{35}$` |
| Entropy | none |
| Keywords | none (structure is the anchor: numeric bot ID + colon + token) |
| Other | HTTP verification against `api.telegram.org/bot{token}/getMe`; `^` and `$` anchors require full-line mode |
| Portability | HIGH |
| Port Notes | Rust regex (without line anchors for inline scanning): `\d{8,10}:[0-9A-Za-z_-]{35}`. The `^` and `$` anchors are Python re line anchors — in Rust use `(?m)` flag or remove them for inline scanning. The format `NNNNNNNNN:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` is distinctive — numeric ID followed by colon followed by exactly 35 base62url chars. Add `\b` before the digit sequence if needed. |

---

### twilio

| Field | Value |
|-------|-------|
| Regex | `AC[a-z0-9]{32}` (Account SID); `SK[a-z0-9]{32}` (Auth token) |
| Entropy | none |
| Keywords | `AC` / `SK` prefix (2-char prefix) |
| Other | none — pure regex |
| Portability | HIGH |
| Port Notes | Rust regex: `AC[a-z0-9]{32}` and `SK[a-z0-9]{32}`. The 2-char prefix is less distinctive than other services (AC/SK are common letter pairs). Add `\b` prefix for precision: `\bAC[a-z0-9]{32}\b` and `\bSK[a-z0-9]{32}\b`. Consider requiring the prefix to be case-insensitive since Twilio docs show uppercase consistently. Note: `SK` prefix collides with some Stripe patterns — ensure the length difference (32 vs 24) provides sufficient disambiguation. |

---

## Corrections to Pre-Assigned Portability

The following pre-assigned portability ratings from the plan differ from the actual code review:

| Plugin | Pre-assigned | Corrected | Reason |
|--------|-------------|-----------|--------|
| azure_storage_key | LOW | HIGH | Actual plugin is pure regex (`AccountKey=[a-zA-Z0-9+\/=]{88}`); no URL parsing found |
| ibm_cloud_iam | HIGH | LOW | Uses `(?![a-zA-Z0-9_-])` negative lookahead — incompatible with Rust regex crate |
| ibm_cos_hmac | HIGH | HIGH | Confirmed; `(?![a-f0-9])` is only incompatible element; easily replaced with `\b` |
| gitlab_token | HIGH | EXCLUDE | All 7 patterns use `(?!\w)` negative lookahead — incompatible; covered by other sources |
