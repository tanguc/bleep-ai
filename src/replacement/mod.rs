mod types;
pub mod replacers;

pub use types::Redaction;

use std::collections::HashMap;

use bytes::Bytes;

use crate::detection::Match;
use crate::types::rule::ReplacementType;

/// apply replaces all matched spans in `body` with typed fake values.
///
/// precondition: `matches` must be sorted descending by span.start (as returned by detection::scan).
///
/// returns (modified_bytes, redactions) where redactions form the forward map for de-anonymization.
/// if matches is empty, returns (body, vec![]) with no allocation.
pub fn apply(body: Bytes, matches: Vec<Match>) -> (Bytes, Vec<Redaction>) {
    // a. early return
    if matches.is_empty() {
        return (body, vec![]);
    }

    // b. per-request dedup map keyed on raw matched bytes
    let mut dedup: HashMap<Vec<u8>, String> = HashMap::new();

    // c. mutable buffer
    let mut buffer: Vec<u8> = body.into();

    let mut redactions: Vec<Redaction> = Vec::with_capacity(matches.len());

    // d. process each match right-to-left (matches already sorted descending by span.start)
    for m in matches {
        // skip passthrough — no splice, no redaction entry
        if m.rule.replacement_type == ReplacementType::Passthrough {
            continue;
        }

        // dedup: same raw bytes -> same fake
        let fake = if let Some(cached) = dedup.get(&m.raw) {
            cached.clone()
        } else {
            let rt_str = replacement_type_str(&m.rule.replacement_type);
            let generated = replacers::generate(rt_str, &m.rule.id, &m.raw);
            dedup.insert(m.raw.clone(), generated.clone());
            generated
        };

        let fake_bytes: Vec<u8> = fake.as_bytes().to_vec();

        // splice: replace span with fake bytes
        buffer.splice(m.span.start..m.span.end, fake_bytes.into_iter());

        redactions.push(Redaction {
            rule_id: m.rule.id.clone(),
            category: format!("{:?}", m.rule.category).to_lowercase(),
            subcategory: m.rule.subcategory.clone(),
            severity: m.rule.severity.clone(),
            original: String::from_utf8_lossy(&m.raw).into_owned(),
            fake,
            span: m.span,
        });
    }

    (Bytes::from(buffer), redactions)
}

/// deanonymize replaces fake values in `body` with their originals using the redaction forward map.
/// exact-string replacement — no regex, no detection.
pub fn deanonymize(body: Bytes, redactions: &[Redaction]) -> Bytes {
    if redactions.is_empty() {
        return body;
    }

    let reverse: Vec<(Vec<u8>, Vec<u8>)> = redactions
        .iter()
        .map(|r| (r.fake.as_bytes().to_vec(), r.original.as_bytes().to_vec()))
        .collect();

    let mut result = body.to_vec();

    for (fake_bytes, original_bytes) in &reverse {
        if fake_bytes.is_empty() {
            continue;
        }
        let mut i = 0;
        let mut out = Vec::with_capacity(result.len());
        while i < result.len() {
            if result[i..].starts_with(fake_bytes) {
                out.extend_from_slice(original_bytes);
                i += fake_bytes.len();
            } else {
                out.push(result[i]);
                i += 1;
            }
        }
        result = out;
    }

    Bytes::from(result)
}

/// json_replace scans and replaces sensitive values in a JSON body.
/// parses body as JSON, walks all string leaf values, runs detection::scan on each,
/// calls apply() on any matches, and re-serializes.
/// if parsing or re-serialization fails, returns original body unchanged with empty redactions.
pub fn json_replace(body: Bytes) -> (Bytes, Vec<Redaction>) {
    use serde_json::Value;

    let mut root: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (body, vec![]),
    };

    let mut all_redactions: Vec<Redaction> = Vec::new();
    walk_json_value(&mut root, &mut all_redactions);

    match serde_json::to_vec(&root) {
        Ok(new_bytes) => (Bytes::from(new_bytes), all_redactions),
        Err(_) => (body, vec![]),
    }
}

fn walk_json_value(value: &mut serde_json::Value, redactions: &mut Vec<Redaction>) {
    match value {
        serde_json::Value::String(s) => {
            // skip embedded binary payloads (data URLs): scanning corrupts the base64
            // and the host API rejects the resulting payload (e.g. Anthropic 400 "Could not process image")
            if s.starts_with("data:") && s.contains(";base64,") {
                return;
            }
            let bytes = Bytes::copy_from_slice(s.as_bytes());
            // use scan_field: individual JSON string values are context-isolated, so the
            // combined pre-filter would reject them even when they contain secrets.
            // scan_field applies per-rule matching without the combined AhoCorasick gate.
            let matches = crate::detection::scan_field(&bytes);
            if !matches.is_empty() {
                let (replaced, mut new_redactions) = apply(bytes, matches);
                *s = String::from_utf8_lossy(&replaced).into_owned();
                redactions.append(&mut new_redactions);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                walk_json_value(item, redactions);
            }
        }
        serde_json::Value::Object(map) => {
            // skip Anthropic image source blocks: {"type":"base64","media_type":"image/...","data":"..."}
            // mutating the base64 `data` field produces an invalid image and the API returns 400.
            if is_binary_source_block(map) {
                return;
            }
            for val in map.values_mut() {
                walk_json_value(val, redactions);
            }
        }
        _ => {} // numbers, bools, null — not scanned
    }
}

fn is_binary_source_block(map: &serde_json::Map<String, serde_json::Value>) -> bool {
    // Anthropic image/document/file source: { type: "base64", media_type: "...", data: "..." }
    let is_base64_source = matches!(map.get("type"), Some(serde_json::Value::String(t)) if t == "base64")
        && map.contains_key("data");
    if is_base64_source {
        return true;
    }
    // any object carrying a media_type with a string data field is treated as opaque binary
    if let (Some(serde_json::Value::String(mt)), Some(serde_json::Value::String(_))) =
        (map.get("media_type"), map.get("data"))
    {
        if mt.starts_with("image/")
            || mt.starts_with("audio/")
            || mt.starts_with("video/")
            || mt == "application/pdf"
        {
            return true;
        }
    }
    false
}

/// map ReplacementType enum variant to its string key used in the generate() dispatch
fn replacement_type_str(rt: &ReplacementType) -> &'static str {
    match rt {
        ReplacementType::FakerEmail => "faker_email",
        ReplacementType::FakerPhone => "faker_phone",
        ReplacementType::FakerSsn => "faker_ssn",
        ReplacementType::FakerCcLuhn => "faker_cc_luhn",
        ReplacementType::FakerIban => "faker_iban",
        ReplacementType::FakerUuid => "faker_uuid",
        ReplacementType::FakerIpv4 => "faker_ipv4",
        ReplacementType::FakerAwsKey => "faker_aws_key",
        ReplacementType::FakerGithubPat => "faker_github_pat",
        ReplacementType::FakerJwt => "faker_jwt",
        ReplacementType::FakerApiKey => "faker_api_key",
        ReplacementType::FakerDbConn => "faker_db_conn",
        ReplacementType::FakerUrlCred => "faker_url_cred",
        ReplacementType::FpeNumeric => "fpe_numeric",
        ReplacementType::GenericRandom => "generic_random",
        ReplacementType::Passthrough => "passthrough",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::rule::{Category, Confidence, NormalizedRule, ReplacementType};
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
        });
        Match {
            rule,
            span,
            raw: raw.to_vec(),
            confidence_boost: false,
        }
    }

    #[test]
    fn test_apply_empty_matches() {
        let body = Bytes::from_static(b"hello world");
        let (result, redactions) = apply(body.clone(), vec![]);
        assert_eq!(result, body, "empty matches should return original body");
        assert!(redactions.is_empty());
    }

    #[test]
    fn test_apply_passthrough_skipped() {
        let body = Bytes::from_static(b"my ip is 192.168.1.1 here");
        let m = make_match(b"192.168.1.1", 9..20, ReplacementType::Passthrough);
        let (result, redactions) = apply(body.clone(), vec![m]);
        assert_eq!(result, body, "passthrough should leave body unchanged");
        assert!(redactions.is_empty(), "passthrough should produce no redactions");
    }

    #[test]
    fn test_apply_dedup_same_raw() {
        // two matches with same raw bytes should get same fake
        let body = Bytes::from_static(b"aaa---aaa");
        let m1 = make_match(b"aaa", 6..9, ReplacementType::GenericRandom);
        let m2 = make_match(b"aaa", 0..3, ReplacementType::GenericRandom);
        // already sorted descending: m1 at 6 first, m2 at 0 second
        let (_, redactions) = apply(body, vec![m1, m2]);
        assert_eq!(redactions.len(), 2);
        assert_eq!(
            redactions[0].fake, redactions[1].fake,
            "same raw bytes must produce same fake"
        );
    }

    #[test]
    fn test_apply_right_to_left_no_corruption() {
        // two non-overlapping spans: replacing right-to-left should not corrupt left span
        let body = Bytes::from_static(b"AAAAA_BBBBB");
        // span 6..11 = "BBBBB", span 0..5 = "AAAAA"
        let m1 = make_match(b"BBBBB", 6..11, ReplacementType::FakerIban);
        let m2 = make_match(b"AAAAA", 0..5, ReplacementType::FakerIban);
        let (result, redactions) = apply(body, vec![m1, m2]);
        assert_eq!(redactions.len(), 2);
        // both spans replaced — result should contain both fakes
        let result_str = String::from_utf8(result.to_vec()).unwrap();
        // both spans replaced with iban-shaped fakes joined by "_"
        let parts: Vec<&str> = result_str.split('_').collect();
        assert_eq!(parts.len(), 2, "result should still have _ separator: {}", result_str);
        // verify each half is iban-shaped (2-letter country + alnum, default GB22)
        for part in &parts {
            assert!(
                part.len() >= 15 && part.len() <= 34,
                "each half should be iban-shaped (15-34 chars): {}",
                part
            );
            assert!(
                part.bytes().take(2).all(|b| b.is_ascii_uppercase()),
                "iban must start with 2 uppercase country letters: {}",
                part
            );
        }
    }

    #[test]
    fn test_deanonymize_empty_redactions() {
        let body = Bytes::from_static(b"hello world");
        let result = deanonymize(body.clone(), &[]);
        assert_eq!(result, body);
    }

    #[test]
    fn test_deanonymize_restores_original() {
        let body = Bytes::from_static(b"secret_value");
        let m = make_match(b"secret_value", 0..12, ReplacementType::FakerApiKey);
        let (replaced, redactions) = apply(body.clone(), vec![m]);
        assert_ne!(replaced, body, "apply should have changed the body");

        let restored = deanonymize(replaced, &redactions);
        assert_eq!(restored, body, "deanonymize must restore original");
    }

    #[test]
    fn test_deanonymize_multiple_occurrences() {
        // deanonymize must handle the fake appearing twice
        let fake = "fakeval";
        let original = "realval";
        let r1 = Redaction {
            rule_id: "r".to_string(),
            category: "secret".to_string(),
            subcategory: "generic".to_string(),
            severity: "medium".to_string(),
            original: original.to_string(),
            fake: fake.to_string(),
            span: 0..7,
        };
        let body_str = format!("{}_separator_{}", fake, fake);
        let body = Bytes::from(body_str);
        let result = deanonymize(body, &[r1]);
        let result_str = String::from_utf8(result.to_vec()).unwrap();
        let expected = format!("{}_separator_{}", original, original);
        assert_eq!(result_str, expected);
    }

    #[test]
    fn test_json_replace_clean_body() {
        let body = Bytes::from_static(b"{\"key\":\"clean value\"}");
        let (result, redactions) = json_replace(body.clone());
        let result_val: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(redactions.is_empty(), "clean body should have 0 redactions");
        assert_eq!(result_val["key"], "clean value");
    }

    #[test]
    fn test_json_replace_invalid_json() {
        let body = Bytes::from_static(b"not json {{{");
        let (result, redactions) = json_replace(body.clone());
        assert_eq!(result, body, "invalid JSON must return original unchanged");
        assert!(redactions.is_empty());
    }

    #[test]
    fn test_json_replace_produces_valid_json() {
        // any body that goes through json_replace must produce parseable JSON
        let body = Bytes::from_static(b"{\"nested\":{\"arr\":[\"value1\",\"value2\"]}}");
        let (result, _) = json_replace(body);
        serde_json::from_slice::<serde_json::Value>(&result)
            .expect("json_replace output must be valid JSON");
    }
}
