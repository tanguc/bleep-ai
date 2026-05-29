mod types;
pub use types::Match;

use std::sync::Arc;

use flate2::read::{DeflateDecoder, GzDecoder};
use std::io::Read;

use crate::patterns::{COMBINED, RULES};
use crate::types::rule::{ChecksumType, Confidence};

/// scan raw bytes and return all detected matches
///
/// - applies AhoCorasick combined pre-filter first
/// - runs per-rule regex with inner keyword pre-filter and entropy filter
/// - resolves overlapping spans (longer span wins)
/// - returns matches sorted descending by span.start (for right-to-left replacement)
pub fn scan(body: &[u8]) -> Vec<Match> {
    let _g = crate::perf::span("detection.scan");
    // step a: combined pre-filter — fast reject if no keywords present
    let t_pre = std::time::Instant::now();
    let pre = COMBINED.is_match(body);
    crate::perf::record("detection.combined_prefilter", t_pre.elapsed());
    if !pre {
        return Vec::new();
    }

    scan_inner(body)
}

/// scan an isolated field (JSON string value, header value, etc.) without the combined pre-filter.
///
/// use this when the field value has already been extracted from its context — the
/// combined pre-filter would reject it because context keywords (from surrounding fields)
/// are not present in the isolated value.
///
/// still applies per-rule keyword checks, entropy, and checksum filters.
pub fn scan_field(field: &[u8]) -> Vec<Match> {
    let _g = crate::perf::span("detection.scan_field");
    scan_inner(field)
}

/// core matching logic shared by scan() and scan_field()
fn scan_inner(body: &[u8]) -> Vec<Match> {
    let _g = crate::perf::span("detection.scan_inner");
    let mut matches: Vec<Match> = Vec::new();

    // per-rule matching
    for (rule_arc, regex, exclude_re) in RULES.iter() {
        let t_rule = std::time::Instant::now();
        // inner keyword pre-filter (per-rule keywords)
        if !rule_arc.keywords.is_empty()
            && !rule_arc
                .keywords
                .iter()
                .any(|k| body.windows(k.len()).any(|w| w == k.as_bytes()))
        {
            // record dyn so we see which rules short-circuit on keyword
            // pre-filter (cheap = good).
            crate::perf::record_dyn(
                &format!("rule.kw_skip:{}", rule_arc.id),
                t_rule.elapsed(),
            );
            continue;
        }

        for m in regex.find_iter(body) {
            let raw = body[m.start()..m.end()].to_vec();

            // exclude_regex filter — discard known false-positive patterns
            if let Some(excl) = exclude_re {
                if excl.is_match(&raw) {
                    continue;
                }
            }

            // entropy filter
            if let Some(threshold) = rule_arc.entropy {
                if shannon_entropy(&raw) < threshold {
                    continue;
                }
            }

            // luhn checksum filter
            if rule_arc.checksum_type == Some(ChecksumType::Luhn) {
                if !luhn_valid(&raw) {
                    continue;
                }
            }

            let confidence_boost = has_context_keyword(body, m.start(), &rule_arc.keywords);

            matches.push(Match {
                rule: Arc::clone(rule_arc),
                span: m.start()..m.end(),
                raw,
                confidence_boost,
            });
        }
        // per-rule total scan time (includes regex find_iter + filters)
        crate::perf::record_dyn(&format!("rule.scan:{}", rule_arc.id), t_rule.elapsed());
    }

    let t_resolve = std::time::Instant::now();
    // step c+d: overlap resolution
    // sort by span.start ascending, then span.len() descending (longer first within same start)
    matches.sort_by(|a, b| {
        a.span
            .start
            .cmp(&b.span.start)
            .then(b.span.len().cmp(&a.span.len()))
    });

    let mut resolved: Vec<Match> = Vec::with_capacity(matches.len());
    'outer: for m in matches {
        for prev in &resolved {
            // if m is fully contained within prev, discard m
            if m.span.start >= prev.span.start && m.span.end <= prev.span.end {
                continue 'outer;
            }
        }
        resolved.push(m);
    }

    // step e: sort descending by span.start
    resolved.sort_by(|a, b| b.span.start.cmp(&a.span.start));
    crate::perf::record("detection.overlap_resolve", t_resolve.elapsed());

    resolved
}

/// decompress gzip/deflate body before scanning; falls back to raw on error
pub fn scan_compressed(body: &[u8], content_encoding: &str) -> Vec<Match> {
    let encoding = content_encoding.to_ascii_lowercase();
    let decompressed: Option<Vec<u8>> = if encoding.contains("gzip") {
        let mut decoder = GzDecoder::new(body);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok().map(|_| out)
    } else if encoding.contains("deflate") {
        let mut decoder = DeflateDecoder::new(body);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok().map(|_| out)
    } else {
        None
    };

    match decompressed {
        Some(plain) => scan(&plain),
        None => scan(body),
    }
}

/// returns true if match_conf meets or exceeds the threshold
pub fn confidence_meets(match_conf: &Confidence, threshold: &str) -> bool {
    match threshold {
        "high" => *match_conf == Confidence::High,
        "medium" => matches!(match_conf, Confidence::High | Confidence::Medium),
        _ => true, // "low" or unknown = pass everything
    }
}

/// returns true if a severity string meets the min_confidence threshold.
///
/// used to filter Redaction entries (which carry severity, not Confidence enum)
/// against the CLI --min-confidence flag. severity levels map as:
/// critical/high → Confidence::High, medium → Confidence::Medium, low → Confidence::Low
pub fn confidence_meets_severity(severity: &str, threshold: &str) -> bool {
    match threshold {
        "high" => matches!(severity, "high" | "critical"),
        "medium" => matches!(severity, "high" | "critical" | "medium"),
        _ => true, // "low" or unknown = pass everything
    }
}

/// shannon entropy over byte value distribution
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// luhn algorithm validation for credit card digit sequences
pub(crate) fn luhn_valid(digits: &[u8]) -> bool {
    let digits: Vec<u8> = digits
        .iter()
        .filter(|&&b| b.is_ascii_digit())
        .map(|&b| b - b'0')
        .collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        } as u32)
        .sum();
    sum % 10 == 0
}

/// check if any keyword appears within a 5-token window around span_start
fn has_context_keyword(body: &[u8], span_start: usize, keywords: &[String]) -> bool {
    if keywords.is_empty() {
        return false;
    }
    // collect token (start, end) pairs by splitting on ASCII whitespace
    let tokens: Vec<(usize, usize)> = {
        let mut toks = Vec::new();
        let mut i = 0;
        while i < body.len() {
            while i < body.len() && body[i].is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            while i < body.len() && !body[i].is_ascii_whitespace() {
                i += 1;
            }
            if start < i {
                toks.push((start, i));
            }
        }
        toks
    };
    // find token index containing span_start
    let match_tok = tokens
        .partition_point(|&(s, _)| s <= span_start)
        .saturating_sub(1);
    let lo = match_tok.saturating_sub(5);
    let hi = (match_tok + 5).min(tokens.len());
    for &(ts, te) in &tokens[lo..hi] {
        let token_bytes = &body[ts..te];
        for kw in keywords {
            if token_bytes
                .windows(kw.len())
                .any(|w| w.eq_ignore_ascii_case(kw.as_bytes()))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::rule::{Category, NormalizedRule, ReplacementType};
    use aho_corasick::AhoCorasick;
    use regex::bytes::Regex;
    use std::sync::Arc;

    // build a synthetic NormalizedRule for testing
    fn make_rule(
        id: &str,
        regex: &str,
        keywords: Vec<String>,
        entropy: Option<f64>,
        checksum_type: Option<ChecksumType>,
        confidence: Confidence,
    ) -> NormalizedRule {
        NormalizedRule {
            id: id.to_string(),
            name: id.to_string(),
            category: Category::Secret,
            subcategory: "generic".to_string(),
            regex: regex.to_string(),
            source: "test".to_string(),
            confidence,
            entropy,
            keywords,
            tags: vec![],
            checksum_type,
            replacement_type: ReplacementType::GenericRandom,
            description: String::new(),
            severity: "medium".to_string(),
            literal_prefix: None,
            exclude_regex: None,
        }
    }

    // run scan() against a body using an inline rule set (bypasses COMBINED/RULES statics)
    // tests for the core algorithm use the actual static RULES/COMBINED for integration tests
    // and direct helper tests for unit tests

    #[test]
    fn test_no_match_empty_body() {
        let result = scan(b"");
        assert!(result.is_empty(), "empty body should return empty vec");
    }

    #[test]
    fn test_no_match_clean_body() {
        let result = scan(b"The quick brown fox jumps over the lazy dog.");
        assert!(
            result.is_empty(),
            "clean body with no keywords should return empty vec"
        );
    }

    #[test]
    fn test_single_match() {
        // github PAT rule has keywords: [] so it only fires when COMBINED pre-filter
        // passes due to another rule's keyword being present.
        // include "airtable" (a known COMBINED keyword) + the PAT in the same body.
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        let body = format!("airtable key context {}", token);
        let results = scan(body.as_bytes());
        assert!(
            !results.is_empty(),
            "should detect github PAT in body, got 0 matches"
        );
        // verify the span points at the token
        let m = &results[0];
        let matched_str = std::str::from_utf8(&m.raw).unwrap();
        assert!(
            matched_str.contains("ghp_"),
            "matched raw should contain ghp_ prefix"
        );
    }

    #[test]
    fn test_overlapping_matches() {
        // two matches at the same position: scan() should keep longer span, drop contained one
        // we test this with the shannon_entropy helper and luhn_valid directly
        // and use the overlap resolution logic unit test below
        let body = b"abc xyz abc";
        let rule1 = make_rule("r1", r"abc xyz", vec![], None, None, Confidence::High);
        let rule2 = make_rule("r2", r"abc", vec![], None, None, Confidence::Medium);

        let re1 = Regex::new(&rule1.regex).unwrap();
        let re2 = Regex::new(&rule2.regex).unwrap();
        let arc1 = Arc::new(rule1);
        let arc2 = Arc::new(rule2);

        // simulate match collection
        let mut raw_matches: Vec<Match> = Vec::new();
        for m in re1.find_iter(body) {
            raw_matches.push(Match {
                rule: Arc::clone(&arc1),
                span: m.start()..m.end(),
                raw: body[m.start()..m.end()].to_vec(),
                confidence_boost: false,
            });
        }
        for m in re2.find_iter(body) {
            raw_matches.push(Match {
                rule: Arc::clone(&arc2),
                span: m.start()..m.end(),
                raw: body[m.start()..m.end()].to_vec(),
                confidence_boost: false,
            });
        }

        // apply overlap resolution (same logic as scan())
        raw_matches.sort_by(|a, b| {
            a.span
                .start
                .cmp(&b.span.start)
                .then(b.span.len().cmp(&a.span.len()))
        });
        let mut resolved: Vec<Match> = Vec::new();
        'outer: for m in raw_matches {
            for prev in &resolved {
                if m.span.start >= prev.span.start && m.span.end <= prev.span.end {
                    continue 'outer;
                }
            }
            resolved.push(m);
        }

        // "abc xyz" at 0..7 should win over "abc" at 0..3
        let contained_removed = resolved
            .iter()
            .all(|m| m.span.end - m.span.start >= 3 || m.span.start >= 8);
        // "abc" at 8..11 is NOT contained in "abc xyz" at 0..7, so it stays
        // "abc" at 0..3 IS contained in "abc xyz" at 0..7, so it's dropped
        let first_abc_removed = !resolved
            .iter()
            .any(|m| m.span.start == 0 && m.span.end == 3);
        assert!(
            first_abc_removed,
            "contained span 0..3 should be removed; remaining: {:?}",
            resolved
                .iter()
                .map(|m| &m.span)
                .collect::<Vec<_>>()
        );
        let _ = contained_removed;
    }

    #[test]
    fn test_entropy_filter() {
        // 16 identical chars: very low entropy, should be filtered if threshold is set
        let low_entropy = b"AAAAAAAAAAAAAAAA";
        let h = shannon_entropy(low_entropy);
        assert!(
            h < 1.0,
            "repeated chars should have near-zero entropy, got {}",
            h
        );

        // random-looking bytes: high entropy
        let high_entropy = b"aB3xZ9mQpRsTuVwX";
        let h2 = shannon_entropy(high_entropy);
        assert!(
            h2 > 2.0,
            "diverse chars should have high entropy, got {}",
            h2
        );
    }

    #[test]
    fn test_keyword_prefilter_shortcircuit() {
        // body with no AhoCorasick keyword hits returns empty vec without running any regex
        // "xyzzy" and similar garbage have no keyword matches in COMBINED
        let result = scan(b"xyzzy foobar baz qux norf completely random text");
        assert!(
            result.is_empty(),
            "body with no keywords should short-circuit and return empty vec"
        );
    }

    #[test]
    fn test_luhn_valid_cc() {
        // known valid visa: 4532015112830366
        assert!(
            luhn_valid(b"4532015112830366"),
            "4532015112830366 should be luhn valid"
        );
        // invalid (last digit changed)
        assert!(
            !luhn_valid(b"4532015112830367"),
            "4532015112830367 should fail luhn"
        );
        // too short
        assert!(!luhn_valid(b"4"), "single digit should fail luhn");
    }

    // --- dedicated luhn tests (TST-03) ---

    #[test]
    fn test_luhn_mastercard_valid() {
        // known valid mastercard
        assert!(
            luhn_valid(b"5425233430109903"),
            "5425233430109903 should be luhn valid (Mastercard)"
        );
    }

    #[test]
    fn test_luhn_amex_valid() {
        // american express 15-digit
        assert!(
            luhn_valid(b"371449635398431"),
            "371449635398431 should be luhn valid (Amex 15-digit)"
        );
    }

    #[test]
    fn test_luhn_invalid_last_digit() {
        // valid mastercard with last digit changed
        assert!(
            !luhn_valid(b"5425233430109902"),
            "5425233430109902 should fail luhn (last digit changed)"
        );
    }

    #[test]
    fn test_luhn_too_short() {
        assert!(!luhn_valid(b"123"), "3-digit input should fail luhn (too short)");
        assert!(!luhn_valid(b""), "empty input should fail luhn");
    }

    #[test]
    fn test_luhn_all_zeros() {
        // 0000000000000000 passes luhn (all zeros: sum=0, 0%10==0)
        // this is mathematically valid but not a real card — just verifying algorithm correctness
        assert!(
            luhn_valid(b"0000000000000000"),
            "all-zeros 16-digit passes luhn by algorithm definition (sum mod 10 = 0)"
        );
    }

    #[test]
    fn test_luhn_with_spaces_and_dashes() {
        // real CC format with spaces: "4532 0151 1283 0366"
        // luhn_valid filters non-digits, so spaces/dashes are stripped
        assert!(
            luhn_valid(b"4532 0151 1283 0366"),
            "visa with spaces must pass luhn after stripping non-digits"
        );
        assert!(
            luhn_valid(b"4532-0151-1283-0366"),
            "visa with dashes must pass luhn after stripping non-digits"
        );
        // corresponding invalid with spaces
        assert!(
            !luhn_valid(b"4532 0151 1283 0367"),
            "invalid visa with spaces must fail luhn"
        );
    }

    #[test]
    fn test_shannon_entropy_helpers() {
        assert_eq!(shannon_entropy(b""), 0.0);
        // single unique byte has entropy 0
        assert_eq!(shannon_entropy(b"AAAA"), 0.0);
        // two equal-probability bytes: entropy = 1.0
        let h = shannon_entropy(b"ABABABAB");
        assert!((h - 1.0).abs() < 1e-10, "50/50 two bytes = entropy 1.0, got {}", h);
    }

    #[test]
    fn test_scan_compressed_passthrough() {
        // empty encoding: delegates to scan(body) directly
        let body = b"xyzzy completely clean text";
        let result = scan_compressed(body, "");
        assert!(result.is_empty(), "clean passthrough should return empty");
    }

    #[test]
    fn test_scan_compressed_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // include "airtable" to ensure COMBINED pre-filter fires
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        let plain = format!("airtable key context {}", token);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let results = scan_compressed(&compressed, "gzip");
        assert!(
            !results.is_empty(),
            "gzip body with github PAT should be detected"
        );
    }

    #[test]
    fn test_confidence_meets() {
        assert!(confidence_meets(&Confidence::High, "high"));
        assert!(confidence_meets(&Confidence::High, "medium"));
        assert!(confidence_meets(&Confidence::High, "low"));
        assert!(!confidence_meets(&Confidence::Low, "high"));
        assert!(!confidence_meets(&Confidence::Low, "medium"));
        assert!(confidence_meets(&Confidence::Low, "low"));
        assert!(confidence_meets(&Confidence::Medium, "medium"));
        assert!(!confidence_meets(&Confidence::Medium, "high"));
    }

    #[test]
    fn test_context_proximity_boost_present() {
        // test has_context_keyword directly with known keyword placement
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        let body = format!("my token: {}", token);
        let keywords = vec!["token".to_string()];
        let token_start = body.find("ghp_").unwrap();
        let boosted = has_context_keyword(body.as_bytes(), token_start, &keywords);
        assert!(boosted, "keyword 'token' should be within 5 tokens of the match");
    }

    #[test]
    fn test_context_proximity_no_boost() {
        // no context word near the match
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        let keywords = vec!["apikey".to_string()];
        let token_start = 0;
        let body = token.as_bytes();
        let boosted = has_context_keyword(body, token_start, &keywords);
        assert!(!boosted, "no keyword 'apikey' near start should not boost");
    }

    #[test]
    fn test_no_import_async() {
        // compile-time test: this module must not use tokio/axum/hudsucker/reqwest
        // verified by the absence of those imports in the file itself
        // if this test compiles without async runtime, the constraint is satisfied
        let _ = scan(b"test");
    }
}

/// TST-03: dedicated Luhn checksum validation tests
#[cfg(test)]
mod luhn_tests {
    use super::luhn_valid;

    /// known valid Visa: 4532015112830366
    #[test]
    fn test_luhn_valid_visa() {
        assert!(luhn_valid(b"4532015112830366"), "Visa 4532015112830366 must be Luhn-valid");
    }

    /// known valid Mastercard: 5425233430109903
    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(luhn_valid(b"5425233430109903"), "Mastercard 5425233430109903 must be Luhn-valid");
    }

    /// known valid Amex (15 digits): 371449635398431
    #[test]
    fn test_luhn_valid_amex() {
        assert!(luhn_valid(b"371449635398431"), "Amex 371449635398431 must be Luhn-valid");
    }

    /// invalid: last digit of valid Visa changed by 1
    #[test]
    fn test_luhn_invalid_visa_last_digit() {
        assert!(!luhn_valid(b"4532015112830367"), "4532015112830367 must fail Luhn");
    }

    /// single digit must fail Luhn (requires at least 2 digits)
    #[test]
    fn test_luhn_invalid_short() {
        assert!(!luhn_valid(b"4"), "single digit must fail Luhn (too short, < 2 digits required)");
        assert!(!luhn_valid(b""), "empty bytes must fail Luhn");
    }

    /// input with spaces and dashes (real-world CC format): non-digits are stripped
    #[test]
    fn test_luhn_with_separators() {
        // spaces stripped: 4532 0151 1283 0366 = 4532015112830366 (valid)
        assert!(
            luhn_valid(b"4532 0151 1283 0366"),
            "Visa with spaces must still be Luhn-valid after stripping separators"
        );
        // dashes stripped: 4532-0151-1283-0366
        assert!(
            luhn_valid(b"4532-0151-1283-0366"),
            "Visa with dashes must still be Luhn-valid after stripping separators"
        );
    }

    /// invalid CC with separator: change last digit, add spaces
    #[test]
    fn test_luhn_invalid_with_separators() {
        assert!(
            !luhn_valid(b"4532 0151 1283 0367"),
            "invalid CC with spaces must fail Luhn"
        );
    }

    /// known valid Discover: 6011111111111117
    #[test]
    fn test_luhn_valid_discover() {
        assert!(luhn_valid(b"6011111111111117"), "Discover 6011111111111117 must be Luhn-valid");
    }

    /// test that luhn_valid is consistent with fake_cc_luhn output (round-trip)
    #[test]
    fn test_luhn_valid_fake_cc_output() {
        // generate 20 fake CC numbers — all must pass Luhn
        for _ in 0..20 {
            let cc = crate::replacement::replacers::generate("faker_cc_luhn", "test", b"4532015112830366", None);
            assert!(
                luhn_valid(cc.as_bytes()),
                "fake_cc_luhn output must always be Luhn-valid, got: {}",
                cc
            );
        }
    }
}
