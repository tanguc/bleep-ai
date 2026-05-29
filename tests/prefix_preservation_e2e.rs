//! End-to-end prefix-preservation matrix.
//!
//! For every rule in the embedded ruleset that has a `literal_prefix`, this
//! test mints many random originals that match the rule's regex, drives them
//! through `detect → replace → deanonymize`, and asserts:
//!
//!   1. the fake substituted for the LLM still begins with the rule's literal
//!      prefix (the bug that motivated this work: HuggingFace `hf_…` tokens
//!      were getting replaced by `Az_…` because `fake_api_key_realistic` was
//!      rerolling the prefix bytes);
//!   2. the fake still matches the rule's own regex — so re-detection on the
//!      LLM's response side stays consistent;
//!   3. deanonymize restores the original byte-for-byte.
//!
//! The matrix is intentionally large (≥ 100 rules × N samples) so that any
//! prefix-class regression — for any vendor token format we know about — gets
//! caught by a single `cargo test` invocation.
//!
//! We exclude rules whose `replacement_type` is not one of the prefix-aware
//! realistic generators (`faker_api_key`, `generic_random`) because the others
//! (`faker_aws_key`, `faker_github_pat`, `faker_jwt`) have their own bespoke
//! prefix-handling logic, and `faker_email`/`faker_phone`/etc. are not secrets
//! that carry a regex-extractable literal prefix.

use bleep_gateway::detection;
use bleep_gateway::patterns::{NORMALIZED_RULES, RULES};
use bleep_gateway::replacement::apply;
use bytes::Bytes;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use regex::bytes::Regex;
use std::collections::HashSet;

/// Per-rule sample count. Total assertions = SAMPLES × #rules-with-prefix,
/// typically ~100-200 rules → hundreds-to-thousands of combinations.
const SAMPLES_PER_RULE: usize = 5;

/// Returns a fresh seeded RNG so test runs are deterministic. We do NOT use
/// thread_rng because flakiness in a 1000-case matrix is unacceptable.
fn rng_for(rule_id: &str) -> StdRng {
    let mut seed = [0u8; 32];
    for (i, b) in rule_id.bytes().enumerate() {
        seed[i % 32] ^= b;
    }
    StdRng::from_seed(seed)
}

/// Mint a random alphanumeric tail of length `n` using a charset broad enough
/// to satisfy most `[A-Za-z0-9_-]+` style suffixes. We deliberately use a
/// subset that's safe for nearly every secret regex (alphanumeric only) so
/// the generator works without parsing each rule's char class.
fn random_tail(rng: &mut StdRng, n: usize) -> Vec<u8> {
    const CS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n).map(|_| CS[rng.gen_range(0..CS.len())]).collect()
}

/// Best-effort minimum-tail-length probe.
///
/// We synthesize candidate tokens at lengths from 16 up to 80 and return the
/// shortest length at which the rule's regex matches. If nothing matches we
/// return `None` and the caller skips this rule.
///
/// We do *not* try to parse the regex AST to recover the exact `{m,n}` range,
/// because the rule corpus mixes Rust-regex flavors and we'd reinvent a
/// regex-engine half. Probing is cheap (one regex find per length).
fn discover_sample(
    rng: &mut StdRng,
    prefix: &str,
    re: &Regex,
) -> Option<Vec<u8>> {
    for tail_len in [20usize, 24, 28, 30, 32, 34, 36, 40, 48, 56, 64, 72, 80] {
        for _ in 0..4 {
            let mut candidate = prefix.as_bytes().to_vec();
            candidate.extend_from_slice(&random_tail(rng, tail_len));
            if re.is_match(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn e2e_prefix_preservation_full_corpus() {
    // ensure visible-marker mode is OFF (realistic mimicry is what we're testing)
    // safety: tests run in isolation; this env var is read once via OnceLock,
    // and we set it before that first read. Setting it again is idempotent.
    unsafe { std::env::remove_var("BLEEP_VISIBLE_MARKERS"); }

    let mut tested_rules = 0usize;
    let mut total_assertions = 0usize;
    let mut skipped_rules: Vec<String> = Vec::new();
    let mut prefix_seen: HashSet<String> = HashSet::new();
    let mut failures: Vec<String> = Vec::new();

    // index regexes by rule id for quick lookup against the validated runtime corpus
    let regex_by_id: std::collections::HashMap<&str, &Regex> = RULES
        .iter()
        .map(|(r, re, _excl)| (r.id.as_str(), re))
        .collect();

    for rule in NORMALIZED_RULES.iter() {
        let Some(prefix) = rule.literal_prefix.as_deref() else {
            continue;
        };
        // only test the realistic generators that we taught about prefixes —
        // the others (faker_aws_key, faker_github_pat, faker_jwt) have their
        // own prefix logic which is covered by replacers.rs unit tests.
        if rule.replacement_type != bleep_gateway::types::rule::ReplacementType::FakerApiKey
            && rule.replacement_type != bleep_gateway::types::rule::ReplacementType::GenericRandom
        {
            continue;
        }
        let Some(re) = regex_by_id.get(rule.id.as_str()) else {
            skipped_rules.push(format!("{}: no compiled regex", rule.id));
            continue;
        };

        let mut rng = rng_for(&rule.id);

        // build samples that the rule's own regex accepts
        let mut samples: Vec<Vec<u8>> = Vec::with_capacity(SAMPLES_PER_RULE);
        for _ in 0..SAMPLES_PER_RULE {
            if let Some(s) = discover_sample(&mut rng, prefix, re) {
                samples.push(s);
            }
        }

        if samples.is_empty() {
            // can't probe — e.g. rule needs specific suffix structure we don't
            // synthesize (UUID dashes, base64 padding, etc.). Not a bug; skip.
            skipped_rules.push(format!("{}: no synthesizable sample", rule.id));
            continue;
        }

        tested_rules += 1;
        prefix_seen.insert(prefix.to_string());

        for original in &samples {
            // wrap in a plausible JSON-ish body so detection's pre-filter has
            // surrounding context. Use the rule's first keyword if any —
            // otherwise raw value (rules without keywords skip the pre-filter).
            let context_kw = rule
                .keywords
                .first()
                .cloned()
                .unwrap_or_else(|| String::new());
            let body_str = if context_kw.is_empty() {
                format!(
                    "{{\"token\":\"{}\"}}",
                    String::from_utf8_lossy(original)
                )
            } else {
                format!(
                    "{{\"{}\":\"{}\"}}",
                    context_kw,
                    String::from_utf8_lossy(original)
                )
            };
            let body = Bytes::from(body_str.into_bytes());

            let matches = detection::scan(&body);
            // we don't assert detection match-count == 1 because some rules
            // overlap in the corpus (a single token can hit gl.* and custom.*
            // for the same vendor — that's intentional precedence layering).
            // We just need *at least one* match for our specific rule.
            let our_match = matches
                .iter()
                .find(|m| m.rule.id == rule.id);

            if our_match.is_none() {
                // some rules need keyword context we didn't provide. Not a
                // bug in prefix preservation — skip silently.
                continue;
            }

            let (redacted_body, redactions) = apply(body.clone(), matches);
            let redacted_str = std::str::from_utf8(&redacted_body).unwrap();

            // find the redaction entry for our rule
            let red = redactions
                .iter()
                .find(|r| r.rule_id == rule.id)
                .expect("our rule matched but produced no redaction entry");

            // ── ASSERTION 1: prefix preserved ───────────────────────────────
            if !red.fake.starts_with(prefix) {
                failures.push(format!(
                    "[{}] fake `{}` does not start with literal_prefix `{}` (original `{}`)",
                    rule.id,
                    red.fake,
                    prefix,
                    String::from_utf8_lossy(original)
                ));
            }
            total_assertions += 1;

            // ── ASSERTION 2: fake still matches the rule's own regex ────────
            // (i.e. the LLM would re-detect this as the same secret class)
            if !re.is_match(red.fake.as_bytes()) {
                failures.push(format!(
                    "[{}] fake `{}` no longer matches rule's regex `{}`",
                    rule.id, red.fake, rule.regex
                ));
            }
            total_assertions += 1;

            // ── ASSERTION 3: deanonymize round-trip ─────────────────────────
            let restored = bleep_gateway::replacement::deanonymize(
                redacted_body.clone(),
                &redactions,
            );
            let restored_str = std::str::from_utf8(&restored).unwrap();
            let original_str = std::str::from_utf8(original).unwrap();
            if !restored_str.contains(original_str) {
                failures.push(format!(
                    "[{}] deanonymize did not restore original `{}` (got `{}`, fake was `{}`)",
                    rule.id, original_str, restored_str, red.fake
                ));
            }
            total_assertions += 1;

            // sanity: the redacted body should not contain the original
            if redacted_str.contains(original_str) {
                failures.push(format!(
                    "[{}] redacted body LEAKS original `{}`: `{}`",
                    rule.id, original_str, redacted_str
                ));
            }
            total_assertions += 1;
        }
    }

    eprintln!(
        "prefix-preservation E2E: {} rules tested, {} distinct prefixes, {} assertions, {} skipped",
        tested_rules,
        prefix_seen.len(),
        total_assertions,
        skipped_rules.len()
    );

    // sanity guardrails: this matrix is meant to be LARGE. if numbers collapse,
    // something is wrong with the rule pipeline or runtime loader.
    assert!(
        tested_rules >= 30,
        "expected >= 30 rules with literal_prefix + prefix-aware replacer, got {}. \
         The matrix has collapsed — check that build-rules ran and that \
         NORMALIZED_RULES is loading the regenerated combined.yaml.",
        tested_rules
    );
    assert!(
        total_assertions >= 200,
        "expected >= 200 assertions in the matrix, got {}",
        total_assertions
    );

    if !failures.is_empty() {
        let preview: Vec<&String> = failures.iter().take(20).collect();
        panic!(
            "prefix-preservation E2E: {} failures (showing first 20):\n{}",
            failures.len(),
            preview
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// Focused regression: the exact bug the user reported — an `hf_…` HuggingFace
/// token must come out as `hf_…` on the downstream side, not `Az_…`.
#[test]
fn regression_hf_token_keeps_prefix() {
    unsafe { std::env::remove_var("BLEEP_VISIBLE_MARKERS"); }

    let original = b"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";
    let body = Bytes::from_static(
        b"{\"huggingface_token\":\"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\"}",
    );
    let matches = detection::scan(&body);
    assert!(
        !matches.is_empty(),
        "HuggingFace token must be detected by the corpus"
    );
    let (redacted, redactions) = apply(body.clone(), matches);
    eprintln!("hf token produced {} redactions:", redactions.len());
    for r in &redactions {
        eprintln!(
            "  rule_id={} original={:?} fake={:?} ({}→{} chars)",
            r.rule_id,
            r.original,
            r.fake,
            r.original.len(),
            r.fake.len()
        );
    }
    let red = redactions
        .iter()
        .find(|r| r.original.contains("hf_"))
        .expect("expected an hf_ redaction");
    assert!(
        red.fake.starts_with("hf_"),
        "HuggingFace fake must preserve the hf_ prefix, got `{}` for original `{}`",
        red.fake,
        red.original
    );
    // deanonymize round-trip
    let restored = bleep_gateway::replacement::deanonymize(redacted, &redactions);
    assert!(
        std::str::from_utf8(&restored)
            .unwrap()
            .contains(std::str::from_utf8(original).unwrap()),
        "deanonymize must restore the original token"
    );
}
