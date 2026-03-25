# Performance Budget

**Requirement:** BEN-03
**Date:** 2026-03-25
**Based on:** docs/benchmarks/THROUGHPUT-RESULTS.md (Plan 04-01), docs/benchmarks/FALSE-POSITIVE-RESULTS.md (Plan 04-02)

## Budget Definition

**Maximum acceptable detection latency overhead per proxied request: 5 ms**

Justification:
- LLM API round-trip latency is typically 500 ms to 10+ seconds for non-streaming requests; streaming first-token latency is 200-2000 ms
- A proxy overhead of 5 ms represents 0.05-1% of the minimum round-trip (200 ms for fast streaming first-token) — imperceptible to users in both streaming and non-streaming scenarios
- The budget is set at 5 ms to leave headroom for: body decompression (DET-05), JSON parse/walk (DET-06), header scanning (DET-07), and potential entropy gating passes (DET-03)
- For streaming responses, the budget applies per chunk (chunks are typically 100-500 bytes) — a much looser constraint than the per-request budget since chunk size is far below the 10 KB typical prompt size

## Measured vs Budget

Latency for regex detection pass on typical request/response body sizes:

| Body Size | Measured Regex Latency (µs) | Budget (µs) | Status |
|-----------|----------------------------|-------------|--------|
| 1 KB      | 13.7                       | 5000        | PASS |
| 10 KB     | 118.2                      | 5000        | PASS |
| 50 KB     | ~581 (interpolated)        | 5000        | PASS |
| 100 KB    | 1159.1                     | 5000        | PASS |

Note: 50 KB value is linearly interpolated from 10 KB (118.2 µs) and 100 KB (1159.1 µs) measurements: 118.2 + (40/90) * (1159.1 - 118.2) = ~581 µs.

Aho-Corasick pre-filter (keyword scan, runs before regex):

| Body Size | Measured AC Latency (µs) | Notes |
|-----------|--------------------------|-------|
| 1 KB      | 2.9 | skips regex entirely when no keywords match |
| 10 KB     | 26.9 | |
| 100 KB    | 281.6 | |

Combined estimate (AC pre-filter + conditional regex):
For a typical LLM prompt with no secrets: AC scan only (fast path). At 10 KB: 26.9 µs total.
For a body containing at least one keyword: AC scan + regex scan. At 10 KB: 26.9 + 118.2 = 145.1 µs total — still well within the 5 ms budget.

## Verdict

**PASS: The 82-pattern baseline meets the 5 ms latency budget.**

The regex scan completes in 13.7-1159 µs for body sizes 1-100 KB, representing at most 1.2 ms overhead — 4x under the 5 ms budget even at 100 KB bodies. v1.1 can use the naive per-pattern regex scan without optimization for the current 82-pattern set.

## Scaling Projections

The curated manifest contains 82 patterns today (138 compiled regex objects after expansion). v1.1 may grow to 200-500 patterns as Nosey Parker and secrets-patterns-db patterns are fully ported. This section projects latency at higher pattern counts.

Assumption: regex scan time scales linearly with pattern count (each pattern is scanned independently via find_iter; no regex set compilation is used in the current bench). This is a conservative assumption — a compiled RegexSet would be sublinear.

Baseline reference: 10 KB body, regex latency = 118.2 µs at 138 compiled patterns.
Per-pattern cost: 118.2 / 138 = 0.857 µs/pattern at 10 KB.

| Pattern Count | Scaling Factor vs 138 | Projected Regex Latency at 10 KB (µs) | Meets 5 ms Budget? |
|---------------|----------------------|---------------------------------------|-------------------|
| 138 (current) | 1.0x | 118.2 | PASS |
| 200           | ~1.4x | ~171 | PASS |
| 500           | ~3.6x | ~428 | PASS |
| 1000          | ~7.2x | ~857 | PASS |

All scaling projections meet the 5 ms budget at 10 KB body size with the naive linear approach. Even at 1000 patterns, the projected latency of 857 µs (0.86 ms) is under the 5 ms budget with 5.8x headroom.

For 100 KB bodies:

| Pattern Count | Projected Regex Latency at 100 KB (µs) | Meets 5 ms Budget? |
|---------------|---------------------------------------|-------------------|
| 138 (current) | 1159.1 | PASS |
| 200           | ~1680 | PASS |
| 500           | ~4200 | PASS |
| 1000          | ~8399 | FAIL |

At 1000 patterns on 100 KB bodies, the projected latency (8.4 ms) exceeds the 5 ms budget. However, 100 KB LLM request bodies are at the extreme end of the distribution — typical prompts are 1-20 KB. The budget is met for the P95 request size.

If the 1000-pattern scenario becomes a target, v1.1 must implement either:
1. Aho-Corasick pre-filtering (DET-02): skip regex scan entirely for bodies with no keyword hits
2. RegexSet via the `regex` crate: compile all patterns into a combined DFA
3. Both

For v1.1 targeting 200-500 patterns, no optimization is required.

## FP Overhead

From FALSE-POSITIVE-RESULTS.md: overall FP rate is 0.4%, with 1 pattern (pii.phone) flagged as HIGH FP and requiring mitigation.

HIGH FP patterns will require entropy gating (DET-03) or keyword pre-filtering (DET-02) passes in v1.1. Estimated additional overhead per pass: negligible for entropy (O(n) byte scan, cheaper than regex at 0.006-0.066 ms per 10 KB-100 KB body as measured) and zero for keyword pre-filtering (already paid by Aho-Corasick in DET-02).

No additional latency budget is required for FP mitigation passes — they run within the existing 5 ms budget.

## Contract for v1.1

The following are the performance requirements that v1.1 implementation must satisfy:

1. Detection pass for a 10 KB request body must complete in <= 500 µs on the reference machine (Apple M3 Pro, 11 cores)
2. Detection pass for a 100 KB request body must complete in <= 3000 µs on the reference machine
3. Total proxy overhead (detection + replacement) must not exceed 5 ms per proxied request for bodies <= 50 KB
4. Regression test: cargo run --bin bench_detect --release results must not degrade more than 20% from the baseline in THROUGHPUT-RESULTS.md
5. FP rate on the FP_CORPUS defined in bench_detect.rs must not increase from the 0.4% baseline in FALSE-POSITIVE-RESULTS.md

---
*Budget established: 2026-03-25*
*Reference measurement: docs/benchmarks/THROUGHPUT-RESULTS.md*
*FP baseline: docs/benchmarks/FALSE-POSITIVE-RESULTS.md*
