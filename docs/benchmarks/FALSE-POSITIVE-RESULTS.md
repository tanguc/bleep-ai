# False Positive Results

**Requirement:** BEN-02
**Date:** 2026-03-25
**Pattern set:** 82 patterns (docs/analysis/CURATED-MANIFEST.md INCLUDE decisions); 138 compiled regex objects
**Corpus:** 20 clean LLM-style samples (src/bin/bench_detect.rs FP_CORPUS)
**Binary:** src/bin/bench_detect.rs

## Summary

| Metric | Value |
|--------|-------|
| Total pattern×sample checks | 2760 |
| Pairs with >=1 FP match      | 12 |
| Overall FP rate              | 0.4% |
| Patterns with zero FP hits   | 128 / 138 (compiled) — ~126 / 138 after accounting for 2 duplicate pattern entries |

## Per-Pattern Breakdown

Patterns that fired on at least one clean corpus sample:

| Pattern Index | Pattern ID | Category | FP Risk (predicted) | Matches on Corpus | Firing Sample(s) |
|---------------|------------|----------|---------------------|-------------------|-----------------|
| 00 | np.aws.1 | secret/aws | LOW | 2 | samples 1 ("AKIAIOSFODNN7EXAMPLE") and 18 ("AKIAXXXXXXXXXXXXXXXX") |
| 06 | np.github.1 | secret/github | LOW | 1 | sample 2 (ghp_ + 36 chars placeholder) |
| 35 | private-key | secret/private-key | LOW | 1 | sample 11 (PEM block header in discussion) |
| 36 | np.postgres.1 | secret/db-conn | LOW | 1 | sample 10 (postgresql://user:password@host) |
| 38 | np.odbc.1 | secret/db-conn | LOW (context-anchored) | 1 | sample 12 (password=12345 in policy text) |
| 39 | np.http.1-url-cred | secret/url-cred | LOW | 1 | sample 10 (URL credential format) |
| 129 | pii.ssn | pii/ssn | MEDIUM | 1 | sample 5 (123-45-6789 as example SSN) |
| 130 | pii.email | pii/email | MEDIUM | 2 | samples 3 (two email addresses in prose) |
| 131 | pii.phone | pii/phone | HIGH | 3 | samples 4 (415-555-0100, 1-800-555-0199) and 1 other |
| 132 | pii.visa-cc | pii/cc | MEDIUM | 1 | sample 6 (4111111111111111 test card number) |

Patterns with zero false positive hits: all remaining 128 patterns (all service-specific tokens, all prefix-anchored SaaS patterns, Aho-Corasick-dependent patterns, and JWT patterns fired zero times on the clean corpus).

## Comparison with Predictions

The FALSE-POSITIVE-ASSESSMENT.md predictions were largely accurate. Patterns rated LOW FP (np.aws.1, private-key, db-conn, url-cred) did fire, but only on corpus samples specifically crafted to include canonical example credentials — these are arguably correct detections of content that a proxy should flag. Patterns rated MEDIUM FP (pii.ssn, pii.email, pii.cc) fired as predicted on example/fictional data. The pii.phone pattern (predicted HIGH FP) fired 3 times, confirming the HIGH FP assessment.

One mild surprise: np.aws.1 (predicted LOW FP) fired on two corpus samples — both on the canonical `AKIAIOSFODNN7EXAMPLE` documentation placeholder. This is the AWS documentation test key that gitleaks and nosey-parker typically allowlist by value. These are detections that a real proxy would need to handle via an allowlist of known documentation examples. All 93+ purely prefix-anchored service token patterns (Anthropic, OpenAI new-format, GitHub fine-grained PAT, GitLab, Stripe, Slack, Doppler, DigitalOcean, Shopify, etc.) produced zero FP hits, confirming the effectiveness of distinctive prefix anchoring for LLM proxy use.

## Patterns Requiring Mitigation in v1.1

Patterns with >2 FP hits on the clean corpus are candidates for additional mitigation in v1.1:
- Entropy gating: require Shannon entropy > threshold before emitting a match
- Keyword pre-filter: require a nearby context keyword (e.g., "password", "secret") before applying the full regex
- Checksum validation: for credit card patterns, apply Luhn check before treating as a match

| Pattern | Hits | Recommended Mitigation |
|---------|------|------------------------|
| pii.phone | 3 | Keyword pre-filter: require "phone", "cell", "tel", "mobile" within 20 chars OR entropy gating (phone numbers have low entropy); consider context-window approach in v1.1 |

Note: All other patterns with FP hits scored 1-2 matches on the 20-sample corpus. For patterns at 1-2 hits, mitigation is optional — the FP rate is already low enough that the raw pattern is acceptable for v1.1. For pii.ssn and pii.email: consider adding domain allowlists for known example domains (example.com, test.org) in v1.1.

## Special Note on np.aws.1 Hits

The two AWS key FP hits (AKIAIOSFODNN7EXAMPLE and AKIAXXXXXXXXXXXXXXXX) are documentation example keys. The gitleaks gitleaks.toml includes allowlist entries for common test values. In v1.1, the detection pass should apply a value allowlist for known documentation placeholders before emitting an alert. This is a Rule 1 fix (bug) not a pattern change.

## Baseline for v1.1

The overall FP rate of 0.4% and per-pattern breakdown established here is the FP baseline. v1.1 implementation of entropy gating and keyword pre-filtering (DET-02, DET-03) must reduce FP rate for the HIGH-hit patterns. Specifically, pii.phone requires mitigation before v1.1 ships. See docs/benchmarks/PERFORMANCE-BUDGET.md (Plan 04-03) for how FP rate feeds into the latency budget.
