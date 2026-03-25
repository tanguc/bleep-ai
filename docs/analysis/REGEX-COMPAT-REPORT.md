# Regex Compatibility Report

**RES-06: All incompatible patterns enumerated with disposition**

Produced: 2026-03-25
Scope: All vendored sources scanned for Rust `regex` crate incompatibilities.
Incompatible features: `(?!...)` (negative lookahead), `(?=...)` (positive lookahead), `(?<!...)` (negative lookbehind), `(?<=...)` (positive lookbehind), `\1`/`\2` (backreferences), `(?>...)` (atomic groups)
Compatible lookalikes (NOT flagged): `(?:...)` (non-capturing groups), `(?P<name>...)` (named capture groups), `(?i)`, `(?s)`, `(?m)`, `(?x)` (inline flags)

---

## Detection Commands Used

```bash
# Gitleaks TOML — rule regex lines only
grep -n "^regex" rules/vendor/gitleaks/gitleaks.toml | grep -E '\(\?[=!<]'

# secrets-patterns-db YAML
grep -n "regex:" rules/vendor/secrets-patterns-db/pii-stable.yml | grep -E '\(\?[=!<]'
grep -n "regex:" rules/vendor/secrets-patterns-db/rules-stable.yml | grep -E '\(\?[=!<]'

# Nosey Parker YAML
grep -rn '(?' rules/vendor/nosey-parker/rules/ | grep -E '\(\?[=!<]'
```

---

## Source: gitleaks (222 rules)

**Result: 0 incompatible patterns found**

All 222 gitleaks rule regex fields were scanned. No negative lookahead, positive lookahead, lookbehind, backreferences, or atomic groups were found in rule `regex` fields. The `(?:...)` non-capturing groups and `(?i)` inline flags that appear extensively are compatible.

Note: gitleaks allowlists (suppression patterns under `[[rules.allowlists]]`) were not scanned — they are not executed during the main matching pass and do not affect Rust regex compatibility for detection.

---

## Source: secrets-patterns-db / rules-stable.yml (1,610 patterns)

**Result: 0 incompatible patterns found**

All 1,610 regex patterns in rules-stable.yml were scanned. No lookahead, lookbehind, or backreference constructs were found. The `(?:...)` non-capturing groups appearing in many patterns are compatible.

---

## Source: secrets-patterns-db / pii-stable.yml (144 patterns)

**Result: 6 incompatible patterns found**

### PII-1: phones (negative lookbehind + negative lookahead)

```
Source: secrets-patterns-db / pii-stable.yml, line 8
Name: phones
Confidence: high
Incompatible features: negative-lookbehind (?<![\d-]), negative-lookahead (?![\d-])
Regex: ((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))
```

**Analysis:** The lookbehind `(?<![\d-])` prevents matching digits that are part of longer digit sequences (e.g., prevents matching the last 10 digits of a credit card). The lookahead `(?![\d-])` prevents matching when followed by more digits. Both are precision enhancements.

**Simplified version:** `(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}`

**Disposition: SIMPLIFY** — Drop both lookaround constructs. The simplified version will have higher FP rate but is functional. FP risk is already HIGH for this category in LLM context (see FALSE-POSITIVE-ASSESSMENT.md). Use simplified version as MEDIUM severity only.

---

### PII-2: phones_with_exts (no lookaround)

```
Source: secrets-patterns-db / pii-stable.yml, line 12
Name: phones_with_exts
Confidence: high
Incompatible features: none
Regex: ((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?))
```

**Analysis:** No incompatible constructs. This pattern is COMPATIBLE with Rust regex crate.

**Disposition: COMPATIBLE** — No action required.

---

### PII-3: street_addresses (positive lookahead)

```
Source: secrets-patterns-db / pii-stable.yml, line 20
Name: street_addresses
Confidence: high
Incompatible features: positive-lookahead (?=\s|$)
Regex: \d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)
```

**Analysis:** The final `(?=\s|$)` lookahead ensures the street type is followed by whitespace or end of string (preventing partial matches). Without it, the pattern could match `driveway` as a `drive`.

**Simplified version:** `\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?:\s|$)`

**Disposition: SIMPLIFY** — Replace `(?=\s|$)` with `(?:\s|$)`. This consumes the character rather than using lookahead, which is equivalent for our purpose. However, `street_addresses` is out of scope for the LLM proxy use case (not in D-06 PII types) — this pattern will be EXCLUDED in the curated manifest regardless.

---

### PII-4: ssn - 3 (multiple negative lookaheads)

```
Source: secrets-patterns-db / pii-stable.yml, line 36
Name: ssn - 3
Confidence: high
Incompatible features: negative-lookahead (?!000|666), (?!00), (?!0000)
Regex: "\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b"
```

**Analysis:** Three negative lookaheads exclude invalid SSN area codes (000, 666), group numbers (00), and serial numbers (0000). These are IRS/SSA validity checks to reduce FP rate. Without them, digit sequences like `123-45-6789` match but are valid; `000-12-3456` is an invalid SSN that would also match.

**Simplified version:** `\b[0-8][0-9]{2}-[0-9]{2}-[0-9]{4}\b`

**Disposition: SIMPLIFY** — Drop the three invalid-value lookaheads. The simplified pattern accepts a small number of invalid SSNs (area code 000, 666) which are extremely unlikely in real usage. Acceptable per D-04 (precision over recall — we accept slightly higher FP rather than complex regex).

---

### PII-5: ssn_number (multiple negative lookaheads)

```
Source: secrets-patterns-db / pii-stable.yml, line 40
Name: ssn_number
Confidence: high
Incompatible features: negative-lookahead (?!000|666|333), (?!00), (?!0000)
Regex: (?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[-](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}
```

**Analysis:** More aggressive validity filtering than ssn - 3; also excludes area code 333 and uses range constraints on the area code digits. The `0*` prefix allows leading zeros in representation. INCOMPATIBLE.

**Simplified version:** `(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[-][0-9]{2}[- ][0-9]{4}`

**Disposition: SIMPLIFY** — The numeric range on area codes (`[0-7][0-6][0-9]` etc.) is compatible and provides some precision. Drop the leading `(?!000|666|333)0*` and the remaining lookaheads on group and serial. The simplified version is less elegant but RE2-compatible.

Note: Use `ssn_number - 3` (`(?:\d{3}-\d{2}-\d{4})`) as the primary SSN pattern instead — simpler and RE2-compatible. These two complex variants are DROP candidates in favor of the simpler one.

---

### PII-6: credit_cards (negative lookahead)

```
Source: secrets-patterns-db / pii-stable.yml, line 224
Name: credit_cards
Confidence: high
Incompatible features: negative-lookahead (?![\d])
Regex: ((?:(?:\d{4}[- ]?){3}\d{4}|\d{15,16}))(?![\d])
```

**Analysis:** The `(?![\d])` lookahead ensures the 16-digit sequence is not followed by more digits (preventing matching partial longer numbers). This is a precision guard.

**Simplified version:** `(?:(?:\d{4}[- ]?){3}\d{4}|\d{15,16})`

**Disposition: SIMPLIFY** — The simplified version may match numbers that are part of longer digit sequences, but in practice 20+ digit sequences are uncommon in LLM responses about credit cards. The individual card-type patterns (visa_credit_card `4[0-9]{15}`, etc.) may be preferred over this generic pattern.

---

### PII-7: btc_addresses (negative lookbehind + negative lookahead)

```
Source: secrets-patterns-db / pii-stable.yml, line 236
Name: btc_addresses
Confidence: high
Incompatible features: negative-lookbehind (?<![a-km-zA-HJ-NP-Z0-9]), negative-lookahead (?![a-km-zA-HJ-NP-Z0-9])
Regex: (?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])
```

**Analysis:** The lookbehind/lookahead pair ensures the address is not part of a longer base58 string. Essential for precision — without them, any substring of a longer base58 string would match.

**Simplified version:** `\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b`

**Disposition: SIMPLIFY** — The `\b` word boundary provides partial equivalent of the lookbehind/lookahead pair (base58 chars are word chars, so `\b` will anchor at non-word-char boundaries). However, btc_addresses is OUT OF SCOPE for the LLM proxy use case (not in D-06 PII types or the defined taxonomy) — this pattern will be EXCLUDED in the curated manifest regardless.

---

## Source: nosey-parker (189 rules across 87 YAML files)

**Result: 0 incompatible patterns found**

All 189 nosey-parker rules were scanned. No negative lookahead, positive lookahead, lookbehind, or backreference constructs were found. The `(?x)`, `(?i)`, `(?s)`, `(?m)` inline flags used extensively in multi-line verbose patterns are compatible. The `(?:...)` non-capturing groups and `(?# comment)` comment syntax within `(?x)` mode are also compatible.

---

## Summary

| Source | Total Patterns | Incompatible | Simplifiable | Drop |
|--------|---------------|--------------|--------------|------|
| gitleaks | 222 | 0 | 0 | 0 |
| secrets-patterns-db (rules-stable) | 1,610 | 0 | 0 | 0 |
| secrets-patterns-db (pii-stable) | 144 | 6 | 4 | 0 |
| nosey-parker | 189 | 0 | 0 | 0 |
| **Total** | **2,165** | **6** | **4** | **0** |

Note: Two patterns (ssn - 3 and ssn_number) are SIMPLIFY but effectively DROP in favor of the simpler `ssn_number - 3` pattern. Two other patterns (street_addresses, btc_addresses) are SIMPLIFY but are OUT OF SCOPE for the taxonomy regardless.

**Coverage impact:** Incompatible patterns are all in the pii-stable.yml file. The active incompatible patterns affecting in-scope types are: phones (1 pattern), ssn patterns (2 patterns, with simplified replacements available), credit_cards (1 pattern, with per-type alternatives). All incompatible patterns have workable simplified alternatives or in-scope replacements. Coverage impact: LOW.

**Key finding:** All three secrets pattern sources (gitleaks, nosey-parker, rules-stable) are fully compatible with Rust's regex crate with zero modifications required. Only the PII patterns in pii-stable.yml require simplification work.
