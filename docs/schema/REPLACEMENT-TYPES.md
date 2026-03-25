# Replacement Type Enum

**Purpose:** Defines all valid values for the `replacement_type` field in [INTERNAL-SCHEMA.md](./INTERNAL-SCHEMA.md). These values drive fake data generation in the v1.1 replacement pipeline (requirements REP-01 through REP-07).

The `replacement_type` enum specifies the *strategy class* for replacement, not implementation details (e.g., what domain to use for fake emails). Implementation choices belong in the Phase 3/v1.1 faker modules.

---

## Enum Values

| Enum Value | Description | When Used |
|------------|-------------|-----------|
| `faker_email` | RFC 5321 valid address; domain is an implementation decision (see note below) | `pii/email` |
| `faker_phone` | E.164-formatted phone number, format-preserving (US or international) | `pii/phone` |
| `faker_ssn` | Valid-format SSN matching `\d{3}-\d{2}-\d{4}`, not a real SSN | `pii/ssn` |
| `faker_cc_luhn` | Luhn-valid credit card number matching the card brand prefix of the original | `pii/cc` |
| `faker_iban` | Valid IBAN format with random account number | `pii/iban` |
| `faker_uuid` | Random UUID v4 | `infra/uuid`, `secret/generic` (UUID-shaped tokens) |
| `faker_ipv4` | Random RFC 1918 private IP address | `infra/ipv4` |
| `faker_aws_key` | AKIA-prefixed 20-char uppercase alphanumeric string | `secret/aws` (access key format) |
| `faker_github_pat` | `ghp_` + 36 alphanumeric characters | `secret/github` (PAT format) |
| `faker_jwt` | Valid-structure JWT with placeholder payload (3-segment base64url, verifiable structure) | `secret/jwt` |
| `faker_api_key` | Random 32-char hex/alphanumeric with source-matching prefix if the pattern has a known prefix; used for most SaaS API tokens | `secret/*` (most SaaS tokens without a dedicated faker) |
| `faker_db_conn` | Connection URI with random host and credentials, preserving the original URI scheme | `secret/db-conn` |
| `faker_url_cred` | URL with `user:pass@` replaced by random credentials | `secret/url-cred`, `infra/url-cred` |
| `fpe_numeric` | Format-preserving encryption (FF1/AES-256) for purely numeric fields; requires key management (Phase 3 architecture concern) | narrow use: numeric IDs where format preservation matters more than realism |
| `generic_random` | Random alphanumeric string matching the length of the original match; explicit fallback for unrecognized patterns | fallback when no specific faker applies |
| `passthrough` | Return the match unchanged — detection fires but no replacement is made | `infra/ipv4` (detection only, LOW severity), debugging |

---

## Per-Category Assignment Table

Maps `category + subcategory` to `replacement_type`. Build.rs consults this table when deriving `replacement_type` for rules that do not have it explicitly set.

| Category | Subcategory | `replacement_type` | Rationale |
|----------|-------------|-------------------|-----------|
| secret | aws (access key) | `faker_aws_key` | maintain AKIA prefix so downstream systems do not break on format validation |
| secret | aws (secret key) | `faker_api_key` | 40-char base64 — generic API key faker with correct length |
| secret | github | `faker_github_pat` | prefix-specific fakers per token type; `ghp_` prefix must be preserved |
| secret | gitlab | `faker_api_key` | `glpat-` / `glptt-` prefix family — faker_api_key with prefix injection |
| secret | anthropic | `faker_api_key` | `sk-ant-api` prefix family |
| secret | openai | `faker_api_key` | `sk-` / `sk-proj-` prefix family |
| secret | stripe | `faker_api_key` | `sk_live_` / `rk_test_` prefix family |
| secret | slack | `faker_api_key` | `xox*-` prefix family |
| secret | jwt | `faker_jwt` | must produce valid 3-segment base64url structure to not break downstream JWT parsers |
| secret | private-key | `faker_api_key` | PEM header replacement only — replaces the `-----BEGIN ... KEY-----` block header |
| secret | db-conn | `faker_db_conn` | URI format preservation required; scheme (postgres://, mysql://, etc.) must be retained |
| secret | url-cred | `faker_url_cred` | `user:pass@` in URI; credentials replaced, rest of URL preserved |
| secret | sendgrid | `faker_api_key` | `SG.` prefix |
| secret | npm | `faker_api_key` | `npm_` prefix |
| secret | pypi | `faker_api_key` | `pypi-` prefix |
| secret | telegram | `faker_api_key` | `numeric:alphanum` format |
| secret | generic | `faker_api_key` | generic SaaS tokens without specific format constraints |
| pii | email | `faker_email` | RFC 5321 valid fake address |
| pii | phone | `faker_phone` | E.164 format-preserving |
| pii | ssn | `faker_ssn` | valid format, not a real SSN |
| pii | cc | `faker_cc_luhn` | Luhn validation ensures generated CC passes format checks in downstream systems |
| pii | iban | `faker_iban` | valid IBAN format with random account number |
| pii | uk-nin | `generic_random` | format-only match; check-digit validation not in RE2; generic random preserves length |
| pii | pl-pesel | `generic_random` | 11-digit PESEL; check-digit not expressible in RE2; generic random preserves format |
| pii | fr-insee | `generic_random` | 15-digit INSEE; Luhn variant not in RE2; generic random preserves format |
| pii | de-taxid | `generic_random` | 11-digit Pruefzahl; check-digit not in RE2; generic random preserves format |
| pii | address | `generic_random` | street addresses — low priority, format too variable for a dedicated faker |
| infra | ipv4 | `passthrough` | ip_public EXCLUDED per Phase 1 analysis; ipv4-private is LOW severity; detection fires, no replacement |
| infra | uuid | `faker_uuid` | random UUID v4 replacement |
| infra | url-cred | `faker_url_cred` | same as secret/url-cred |

---

## Derivation Rules

When `replacement_type` is absent from a rule in the upstream source, build.rs applies these rules in order:

1. `category=secret`, subcategory in assignment table → use the assigned `replacement_type`
2. `category=pii`, subcategory in assignment table → use the assigned `replacement_type`
3. `category=infra`, subcategory=`ipv4` → `passthrough`
4. no match found in table → `generic_random` (explicit fallback)

These rules must be implemented as a pure function in build.rs: `derive_replacement_type(category, subcategory) -> ReplacementType`.

---

## `fpe_numeric` Note

FPE (Format-Preserving Encryption using FF1/AES-256) is specified in v1.1 requirements (REP-03) for purely numeric fields. The schema defines the intent (`replacement_type: fpe_numeric`) but does not encode key management decisions.

Key management (secret key source, key rotation, key injection at startup) is a Phase 3/v1.1 architecture concern. Rules that use `fpe_numeric` require an available encryption key at replacement time; the fake data pipeline must error clearly if no key is configured.

Most numeric PII uses dedicated fakers (`faker_ssn`, `faker_cc_luhn`) rather than raw `fpe_numeric` — these produce realistic fake values without key infrastructure. `fpe_numeric` is reserved for numeric identifiers where format preservation of the *specific numeric encoding* matters more than producing a recognizable fake.

---

## Open Question: Faker Realism

The `replacement_type` enum specifies the strategy class only. Decisions like "use `@example.com` vs a realistic-looking random domain for `faker_email`" are implementation decisions for the Phase 3/v1.1 faker modules. They are intentionally not encoded in the schema enum to keep the schema stable while allowing the implementation to evolve.

See STATE.md research flags: "Fake value realism decision needed for Phase 3/v1.1 fake generators."
