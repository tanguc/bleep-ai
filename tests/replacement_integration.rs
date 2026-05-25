/// Phase 3 integration tests — replacement engine
///
/// covers all 5 success criteria from ROADMAP.md Phase 3
use bytes::Bytes;
use bleep_gateway::replacement::{apply, deanonymize, json_replace, replacers, Redaction};
use bleep_gateway::detection::Match;
use bleep_gateway::types::rule::{Category, Confidence, NormalizedRule, ReplacementType};
use std::sync::Arc;

fn make_match(raw: &[u8], span: std::ops::Range<usize>, rt: ReplacementType) -> Match {
    let rule = Arc::new(NormalizedRule {
        id: "test.rule".to_string(),
        name: "test".to_string(),
        category: Category::Secret,
        subcategory: "generic".to_string(),
        regex: ".+".to_string(),
        source: "test".to_string(),
        confidence: Confidence::High,
        entropy: None,
        keywords: vec![],
        tags: vec![],
        checksum_type: None,
        replacement_type: rt,
        description: String::new(),
        severity: "medium".to_string(),
        literal_prefix: None,
    });
    Match {
        rule,
        span,
        raw: raw.to_vec(),
        confidence_boost: false,
    }
}

/// SC-1: body with two instances of same raw secret → same fake at both positions
/// body length after replacement does not corrupt other spans
#[test]
fn test_sc1_dedup_same_raw_same_fake() {
    // body: "KEY:MYSECRET---KEY:MYSECRET"
    let secret = b"MYSECRET";
    let body = Bytes::from_static(b"KEY:MYSECRET---KEY:MYSECRET");

    // two matches with same raw, sorted descending by span.start
    let m1 = make_match(secret, 19..27, ReplacementType::GenericRandom); // second occurrence
    let m2 = make_match(secret, 4..12, ReplacementType::GenericRandom);  // first occurrence

    let (result, redactions) = apply(body, vec![m1, m2]);

    // both redactions have same fake
    assert_eq!(redactions.len(), 2, "should have 2 redactions");
    assert_eq!(
        redactions[0].fake, redactions[1].fake,
        "same raw bytes must map to same fake: {:?} vs {:?}",
        redactions[0].fake, redactions[1].fake
    );

    // result body still contains the separator and has correct structure
    let result_str = String::from_utf8(result.to_vec()).expect("result must be valid utf8");
    assert!(result_str.contains("KEY:"), "KEY: prefix must be preserved");
    assert!(result_str.contains("---"), "--- separator must be preserved");

    // verify body can be parsed — no corrupted spans
    // count how many times the fake appears (should be 2)
    let fake = &redactions[0].fake;
    let count = result_str.matches(fake.as_str()).count();
    assert_eq!(count, 2, "fake should appear exactly twice, got {}: {}", count, result_str);
}

/// SC-2: each typed generator produces output matching documented format
#[test]
fn test_sc2_typed_fake_formats() {
    // realistic-mode default: replacers mimic input shape, no BLEEP markers

    // email: random handle at one of the RFC 2606 reserved domains
    let email = replacers::generate("faker_email", "r", b"old@real.com", None);
    let email_re = regex::Regex::new(r"^[a-z0-9]+@(example\.com|example\.org|example\.net)$").unwrap();
    assert!(email_re.is_match(&email), "email format mismatch: {}", email);

    // phone: format preserved (separators in same positions, digits randomized)
    let input_phone = "+1 (555) 123-4567";
    let phone = replacers::generate("faker_phone", "r", input_phone.as_bytes(), None);
    assert_eq!(phone.len(), input_phone.len(), "phone length must be preserved: {}", phone);
    for (orig, new) in input_phone.chars().zip(phone.chars()) {
        if !orig.is_ascii_digit() {
            assert_eq!(orig, new, "non-digit char must be preserved: {} vs {}", input_phone, phone);
        }
    }

    // SSN: 9XX area code (unallocated SSA range)
    let ssn = replacers::generate("faker_ssn", "r", b"123-45-6789", None);
    let ssn_re = regex::Regex::new(r"^9\d{2}-\d{2}-\d{4}$").unwrap();
    assert!(ssn_re.is_match(&ssn), "ssn format mismatch: {}", ssn);

    // AWS key: prefix preserved from input, total 20 chars, no BLEEP
    let aws = replacers::generate("faker_aws_key", "r", b"AKIAIOSFODNN7EXAMPLE", None);
    assert_eq!(aws.len(), 20, "aws key must be 20 chars: {}", aws);
    assert!(aws.starts_with("AKIA"), "aws key prefix must be preserved: {}", aws);
    assert!(!aws.contains("BLEEP"), "aws key must not contain BLEEP marker: {}", aws);

    // GitHub PAT: prefix preserved, total 40 chars, no BLEEP
    let pat = replacers::generate("faker_github_pat", "r", b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123", None);
    assert_eq!(pat.len(), 40, "github pat must be 40 chars: {}", pat);
    assert!(pat.starts_with("ghp_"), "github pat prefix must be preserved: {}", pat);
    assert!(!pat.contains("BLEEP"), "github pat must not contain BLEEP marker: {}", pat);
}

/// SC-3: every fake value is JSON-safe when inserted into a JSON string field
#[test]
fn test_sc3_all_types_json_safe() {
    let types: &[(&str, &[u8])] = &[
        ("faker_email", b"old@real.com"),
        ("faker_phone", b"+1-212-555-0100"),
        ("faker_ssn", b"123-45-6789"),
        ("faker_cc_luhn", b"4532015112830366"),
        ("faker_iban", b"GB82WEST12345698765432"),
        ("faker_uuid", b"550e8400-e29b-41d4-a716-446655440000"),
        ("faker_ipv4", b"192.168.1.1"),
        ("faker_aws_key", b"AKIAIOSFODNN7EXAMPLE"),
        ("faker_github_pat", b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"),
        ("faker_jwt", b"eyJ0.eyJ1.sig"),
        ("faker_api_key", b"abc123def456abc123def456abc123de"),
        ("faker_db_conn", b"postgresql://user:pass@host:5432/db"),
        ("faker_url_cred", b"https://admin:pass@api.example.com/v1"),
        ("fpe_numeric", b"123456789"),
        ("generic_random", b"ABCDEF1234"),
    ];

    for (rt, original) in types {
        let fake = replacers::generate(rt, "test-rule", original, None);
        // embed in JSON string and parse — must succeed
        let json_str = format!("\"{}\"", fake);
        serde_json::from_str::<serde_json::Value>(&json_str)
            .unwrap_or_else(|e| panic!("{} produced non-JSON-safe value {:?}: {}", rt, fake, e));
    }
}

/// SC-4: numeric field replacement produces different value of same digit length
#[test]
fn test_sc4_numeric_field_same_length() {
    // fpe_numeric: same digit count
    let orig = b"123456789";
    let result = replacers::generate("fpe_numeric", "r", orig, None);
    assert_eq!(result.len(), orig.len(), "fpe_numeric must preserve length: {} -> {}", std::str::from_utf8(orig).unwrap(), result);
    assert!(result.bytes().all(|b| b.is_ascii_digit()), "fpe output must be all digits: {}", result);

    // generic_random: same length
    let orig2 = b"ABCDEF";
    let result2 = replacers::generate("generic_random", "r", orig2, None);
    assert_eq!(result2.len(), orig2.len(), "generic_random must preserve length");
}

/// SC-5: Vec<Redaction> forward map contains originals; deanonymize restores original string
#[test]
fn test_sc5_forward_map_round_trip() {
    let original_secret = b"MY_SECRET_VALUE";
    let body_str = format!("prefix {} suffix", std::str::from_utf8(original_secret).unwrap());
    let body = Bytes::from(body_str.clone());

    // find the span of the secret in the body
    let secret_start = body_str.find("MY_SECRET_VALUE").unwrap();
    let secret_end = secret_start + original_secret.len();

    let m = make_match(original_secret, secret_start..secret_end, ReplacementType::GenericRandom);

    // apply replacement
    let (replaced_body, redactions) = apply(body.clone(), vec![m]);

    // verify redaction contains the original
    assert_eq!(redactions.len(), 1, "should have 1 redaction");
    assert_eq!(
        redactions[0].original,
        String::from_utf8(original_secret.to_vec()).unwrap(),
        "redaction.original must be the pre-replacement value"
    );

    // the replaced body must differ from the original
    assert_ne!(replaced_body, body, "replacement must change the body");

    // deanonymize must restore the original
    let restored = deanonymize(replaced_body, &redactions);
    assert_eq!(
        restored, body,
        "deanonymize must restore original body"
    );
}

/// additional: json_replace output is always valid JSON
#[test]
fn test_json_replace_valid_output() {
    let bodies: &[&[u8]] = &[
        b"{\"key\":\"value\"}",
        b"[\"a\",\"b\",\"c\"]",
        b"{\"nested\":{\"arr\":[\"x\",\"y\"]}}",
        b"{}",
        b"[]",
        b"null",
        b"\"just a string\"",
    ];
    for body in bodies {
        let (result, _) = json_replace(Bytes::copy_from_slice(body));
        serde_json::from_slice::<serde_json::Value>(&result)
            .unwrap_or_else(|e| panic!("json_replace output is not valid JSON for input {:?}: {}", body, e));
    }
}

/// additional: deanonymize handles multiple fakes in same body
#[test]
fn test_deanonymize_two_different_secrets() {
    let secret1 = b"SECRET_ONE";
    let secret2 = b"SECRET_TWO";
    let body = Bytes::from_static(b"a:SECRET_ONE b:SECRET_TWO end");

    // matches sorted descending by span.start
    // "a:SECRET_ONE b:SECRET_TWO end"
    //   0123456789...
    //   SECRET_ONE at 2..12, SECRET_TWO at 15..25
    let m1 = make_match(secret2, 15..25, ReplacementType::FakerApiKey); // SECRET_TWO at 15..25
    let m2 = make_match(secret1, 2..12, ReplacementType::FakerApiKey);  // SECRET_ONE at 2..12

    let (replaced, redactions) = apply(body.clone(), vec![m1, m2]);
    assert_eq!(redactions.len(), 2);

    // both originals captured
    let originals: Vec<&str> = redactions.iter().map(|r| r.original.as_str()).collect();
    assert!(originals.contains(&"SECRET_ONE"), "SECRET_ONE must be in redactions");
    assert!(originals.contains(&"SECRET_TWO"), "SECRET_TWO must be in redactions");

    // round-trip
    let restored = deanonymize(replaced, &redactions);
    assert_eq!(restored, body, "two-secret round-trip must restore original");
}
