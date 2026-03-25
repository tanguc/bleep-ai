# False Positive Assessment

**Per-pattern FP risk ratings for the LLM proxy context**

Produced: 2026-03-25

## Context: Why LLM Proxy FP Risk Differs

The bleep proxy intercepts LLM API calls — the body is natural language or code, not production data. LLMs are routinely prompted with security tutorials, configuration examples, and developer documentation. This means:

1. LLM responses frequently contain example credentials, configuration snippets, and documentation fragments
2. Pattern types that are highly precise in git-scanning contexts (where code under review is real) have elevated FP rates when applied to LLM conversations
3. PII patterns that work well on real user databases will fire on fictional/example data in LLM responses

**D-04 (precision over recall):** For PII specifically, a missed detection is acceptable if it reduces the false positive rate. LLM responses discussing health, finance, or personal data in general terms should not trigger alerts. Only patterns with high confidence that the matched content is real should be included.

---

## Category: secret/aws

**FP Risk: LOW FP**

AWS access key IDs have distinctive prefix anchors (AKIA, AGPA, AIDA, etc.) that are extremely unlikely to appear in example text. The regex `\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b` requires both a specific 4-letter prefix and exactly 16 uppercase alphanumeric characters.

LLMs do sometimes output AWS documentation examples like `AKIAIOSFODNN7EXAMPLE` — the gitleaks allowlist handles this. The nosey-parker pattern (np.aws.1) includes negative examples for test values.

**Recommendation:** INCLUDE. Use word-boundary-anchored prefix patterns. Entropy metadata from gitleaks (3.0 for access tokens) available as Phase 2 enhancement.

---

## Category: secret/github

**FP Risk: LOW FP**

GitHub token prefixes (ghp_, gho_, ghs_, ghu_, ghr_, github_pat_) are unique to GitHub-issued tokens. The prefix is always followed by a fixed-length base62 string. LLMs occasionally output example tokens with `example` in the value, but the format is distinctive enough that FP rate is very low.

GitHub documentation uses real-looking fake tokens (e.g., `ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`) which use `X` repetition rather than mixed alphanumeric — these won't match.

**Recommendation:** INCLUDE all token types. LOW FP across all GitHub token formats.

---

## Category: secret/anthropic

**FP Risk: LOW FP**

Anthropic API key prefix `sk-ant-api03-` is a distinctive 14-character prefix followed by 95 specific characters. Extremely unlikely to appear coincidentally in LLM output. Claude itself won't output its own real API keys.

**Recommendation:** INCLUDE. Lowest FP risk of all API key types.

---

## Category: secret/openai

**FP Risk: LOW FP**

OpenAI API keys have the sentinel `T3BlbkFJ` embedded in legacy keys, and new project-scoped keys use prefixes `sk-proj-`, `sk-svcacct-`. These are highly distinctive. LLM documentation examples frequently use `sk-...` as placeholder but without the structured suffix.

**Recommendation:** INCLUDE. Use gitleaks pattern that covers both legacy and project-scoped formats.

---

## Category: secret/stripe

**FP Risk: LOW FP**

Stripe keys use `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` prefixes followed by 24 alphanumeric characters. Prefixes are distinctive. LLMs discussing Stripe integration sometimes output example keys like `sk_test_4eC39HqLyjWDarjtT1zdp7dc` — these are real keys in Stripe's documentation and represent genuinely sensitive values.

**Recommendation:** INCLUDE. Note: Stripe test keys (`sk_test_`) are not sensitive to production data but may represent credentials that could be abused to read test transaction data. Include both live and test.

---

## Category: secret/slack

**FP Risk: LOW FP**

Slack token prefixes (`xoxb-`, `xoxp-`, `xoxa-`, `xapp-`, `xoxe-`) are unique to Slack's OAuth token system. The structure `xoxb-NNNN-NNNN-XXXX` is highly distinctive. LLMs discussing Slack bots regularly output example tokens but typically with placeholder values.

**Recommendation:** INCLUDE bot tokens (xoxb-) as HIGH severity. Include other types at MEDIUM severity.

---

## Category: secret/jwt

**FP Risk: MEDIUM FP**

JWT structure is distinctive (`ey[header].[ey[payload].[signature]`) but LLMs discussing authentication, authorization, and API design frequently output JWT examples and decoded payloads. The examples often include real-looking JWTs from tutorials.

Additionally, JWTs in LLM responses may represent:
1. Example tokens from JWT.io or tutorials (not real credentials)
2. Expired tokens in documentation
3. Real tokens that a user included in their prompt (legitimate detection target)

The `ey` base64 prefix is distinctive but the overall pattern is relatively common in developer conversations.

**Recommendation:** INCLUDE at MEDIUM severity. Note that JWT detection without signature key validation cannot determine if the token is real vs example. In Phase 2, consider checking token expiry as a secondary filter.

---

## Category: secret/private-key

**FP Risk: LOW FP**

PEM private key blocks start with `-----BEGIN [TYPE] PRIVATE KEY-----`. This is highly distinctive and represents real sensitive material when present. LLMs discussing cryptography may output example key snippets, but these are typically annotated as examples or deliberately shortened.

**Recommendation:** INCLUDE as HIGH severity.

---

## Category: secret/db-conn

**FP Risk: LOW FP**

Database connection URIs with embedded credentials (`postgres://user:password@host/db`) are specific enough to be low FP. The `user:password@host` pattern requires the `@` separator between credentials and host, which is distinctive.

LLMs discussing database setup will output example connection strings like `postgres://admin:changeme@localhost/mydb` — these are credentials even if they're examples, as users may copy them verbatim.

**Recommendation:** INCLUDE at HIGH severity.

---

## Category: secret/generic (assignment patterns)

**FP Risk: HIGH FP**

Generic assignment patterns (`api_key\s*=\s*`, `secret\s*=\s*`, `password\s*=\s*`) are the primary FP source in the LLM proxy context. LLM responses discussing:
- Configuration file examples
- Security tutorials
- Code snippets with placeholder values
- Documentation for any SaaS service

...all produce variable assignments that match generic patterns. The gitleaks pattern `(?i)[\w.-]{0,50}?service_name(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|...) ` fires on any discussion of service configuration.

An academic study found gitleaks overall precision is ~46%, with generic assignment patterns being the primary contributor to FP. In LLM proxy context, this rate is likely higher given the density of example code in LLM responses.

nosey-parker's `np.generic.2` (api_key/apikey patterns) and gitleaks' ~20 generic assignment rules for SaaS services fall in this category.

**Recommendation:** EXCLUDE generic assignment patterns by default. Include only patterns with a distinctive prefix anchor (like `sk-ant-`, `ghp_`). The value-only patterns without prefix anchoring must pass individual review in Plan 01-03.

Note: The gitleaks pattern for adafruit (`(?i)[\w.-]{0,50}?(?:adafruit)...`) is a service-name-anchored assignment pattern — MEDIUM FP. In LLM context, `adafruit` as a variable name context is uncommon but not impossible in embedded/IoT conversations. Review individually.

---

## Category: pii/ssn

**FP Risk: MEDIUM FP**

US SSN format (`NNN-NN-NNNN`) matches any 9-digit number formatted with hyphens in the pattern `DDD-DD-DDDD`. This can match:
- Phone extension numbers in some formats
- Part numbers with hyphenated 9-digit formats
- Catalog numbers
- Date-like strings in some locales

The `\b[0-8][0-9]{2}-[0-9]{2}-[0-9]{4}\b` simplified pattern (after removing incompatible lookaheads) accepts any value where the first digit is 0-8. This reduces but doesn't eliminate overlap with other formatted number types.

LLMs discussing identity verification, healthcare, or US government processes will generate example SSNs. Common example SSNs like `123-45-6789` and `000-00-0000` exist but the pattern requires first digit 0-8.

Per D-04 (precision over recall): acceptable to miss some real SSNs if it avoids flagging example numbers in health/finance discussions.

**Recommendation:** INCLUDE at HIGH severity with the simplified (lookahead-free) pattern. Accept some FP in exchange for RE2 compatibility.

---

## Category: pii/email

**FP Risk: MEDIUM FP**

LLMs generate example email addresses constantly:
- `user@example.com`, `admin@company.com`, `test@test.com`
- User mentions of their own email in prompts
- Example email content in business writing tasks

The `example.com`, `test.com`, and `localhost` domains are commonly used in non-sensitive contexts. Phase 2 could implement an allowlist of known example domains.

However, emails in LLM prompts may also be real user emails (e.g., "draft an email to john@acme.com") — these are legitimate detection targets for the proxy.

Per D-04: Accept that example emails will be detected. The proxy should use MEDIUM severity and allow downstream systems to decide.

**Recommendation:** INCLUDE at MEDIUM severity. Note precision over recall: use the RFC 5321 compliant pattern which is more precise than the broader `email - 3` variant.

---

## Category: pii/phone

**FP Risk: HIGH FP**

Phone-number-like patterns appear constantly in LLM responses:
- "call us at NNN-NNN-NNNN"
- Serial numbers in format NNN-NNN-NNNN
- Order numbers
- Any 10-digit hyphenated number in US format
- Discussion of phone number formats as examples

The NANP pattern `\d{3}-\d{3}-\d{4}` is far too broad for LLM proxy use. Even the more precise patterns from secrets-patterns-db that validate area codes (first digit 2-9) will fire frequently.

The incompatible phone patterns from secrets-patterns-db (which use lookbehind/lookahead to prevent matching digit sequences that are part of longer numbers) provide some precision improvement, but their simplified versions are less effective.

Per D-04: Prefer precision over recall. In LLM proxy context, the FP rate for phone patterns is unacceptably high without additional context signals.

**Recommendation:** INCLUDE at LOW severity only, or EXCLUDE and add in Phase 2 with better context filtering. If included, use severity LOW to avoid alert fatigue. The incompatible patterns' simplified versions are acceptable only with LOW severity.

---

## Category: pii/cc

**FP Risk: MEDIUM FP**

Credit card numbers (16-digit with specific prefixes: Visa 4, Mastercard 51-55, Amex 34/37) have more structure than SSNs or phone numbers. The per-card-type patterns (4[0-9]{15} for Visa) are more precise than the generic 16-digit pattern.

Without Luhn checksum validation (Phase 2), any 16-digit number with the right prefix matches. LLMs discussing financial topics, account numbers, or data formats may generate 16-digit examples.

The Amex format (3[47][0-9]{13}) is particularly distinctive — 15 digits with 34/37 prefix.

Per D-04: Include per-card-type patterns. The Luhn checksum in Phase 2 will significantly reduce FP for this category.

**Recommendation:** INCLUDE per-card-type patterns at MEDIUM severity. Add Luhn validation in Phase 2. Note the `credit_cards` generic pattern is INCOMPATIBLE (lookahead) — use per-card-type patterns instead.

---

## Category: infra/ipv4-pub

**FP Risk: HIGH FP**

Public IPv4 addresses appear constantly in LLM responses:
- Networking tutorials (`192.168.x.x` examples — private, but also `8.8.8.8`)
- Server configuration discussions
- Security research examples
- DNS/infrastructure discussions

The IPv4 pattern matches any 4-octet number in dotted notation with valid octet ranges. In LLM proxy context, the vast majority of IP addresses in responses are legitimate discussion content, not sensitive data.

Public IPs may be sensitive in some contexts (cloud server IPs, internal network IPs) but detecting them generically produces unacceptable FP rates.

**Recommendation:** EXCLUDE from automated detection OR use INFORMATIONAL severity only. Not suitable as a blocking rule in LLM proxy context.

---

## Category: infra/ipv6

**FP Risk: HIGH FP**

Same reasoning as ipv4-pub. IPv6 addresses appear in networking discussions, documentation, and examples. Full 128-bit notation is distinctive, but LLMs commonly output example addresses.

**Recommendation:** EXCLUDE from automated detection. Not suitable as blocking rule.

---

## Category: infra/url-cred

**FP Risk: LOW FP**

URLs with embedded credentials (`user:password@host`) are unusual in legitimate LLM responses. When they appear, they typically represent real connection strings or configuration examples that users have included in prompts. The `://` + `user:pass@` structure is sufficiently distinctive.

LLMs discussing database connection strings or basic auth configuration may output examples with placeholder credentials (`admin:changeme@localhost`) — these are low-risk but the pattern is correct to flag them since users may copy-paste.

**Recommendation:** INCLUDE at HIGH severity.

---

## High-FP Pattern Specific Flags

The following specific patterns from the vendored sources are known HIGH-FP generators in LLM proxy context based on the regex review:

| Pattern | Source | ID | Reason for HIGH FP |
|---------|--------|----|--------------------|
| Generic API key assignment | gitleaks | generic-api-key | Fires on any `api_key = value` in code discussions |
| Adafruit API key | gitleaks | adafruit-api-key | Assignment pattern with keyword anchor; fires in IoT discussions |
| Adobe client secret | gitleaks | adobe-client-secret | Assignment pattern; common in tutorial code |
| Generic Secret | nosey-parker | np.generic.1 | `secret + 32-64 hex` fires on many hash values in discussions |
| Generic API Key | nosey-parker | np.generic.2 | Assignment patterns for api_key/apikey/access_key |
| phones | secrets-patterns-db | phones | Phone-format patterns; HIGH FP even with lookbehind removed |
| ipv4_address | secrets-patterns-db | ipv4_address | Any IPv4 in networking discussions |
| street_addresses | secrets-patterns-db | street_addresses | Any address-like text in location discussions; out of scope for D-06 |
| btc_addresses | secrets-patterns-db | btc_addresses | INCOMPATIBLE; out of scope for taxonomy |

---

## D-04 Application Summary

Per decision D-04, the following categories apply precision-over-recall:

- **pii/phone**: HIGH FP → EXCLUDE or LOW severity only; acceptable to miss real phone numbers
- **pii/email**: MEDIUM FP → INCLUDE at MEDIUM severity; prefer false negative over false positive for example addresses
- **pii/ssn**: MEDIUM FP → INCLUDE at HIGH severity with simplified pattern; validated area code range provides acceptable precision
- **pii/cc**: MEDIUM FP → INCLUDE at MEDIUM severity; per-card-type patterns preferred; Luhn validation deferred to Phase 2
- **infra/ipv4-pub**: HIGH FP → EXCLUDE; informational at best; not worth blocking rule
- **secret/generic**: HIGH FP → EXCLUDE all generic assignment patterns; only prefix-anchored patterns qualify
