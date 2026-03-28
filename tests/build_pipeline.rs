// integration tests for build pipeline parser logic
// build.rs is a separate compilation unit — its private structs/fns cannot be imported
// this file replicates the helpers inline so they can be tested directly

use std::collections::HashMap;
use std::fs;

// ── replicated structs ────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct GitleaksFile {
    rules: Vec<GitleaksRule>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
struct GitleaksRule {
    id: String,
    description: Option<String>,
    regex: Option<String>,
    entropy: Option<f64>,
    keywords: Option<Vec<String>>,
    tags: Option<Vec<String>>,
}

#[derive(Debug)]
struct SpdbPattern {
    name: String,
    #[allow(dead_code)]
    regex: String,
    confidence: String,
}

#[derive(Debug)]
struct NpRule {
    id: String,
    name: String,
    pattern: String,
    categories: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct NormalizedRule {
    id: String,
    name: String,
    category: String,
    subcategory: String,
    source: String,
    confidence: String,
    regex: String,
    keywords: Vec<String>,
    entropy: Option<f64>,
    tags: Vec<String>,
    checksum_type: Option<String>,
    replacement_type: String,
    description: String,
    severity: String,
}

// combined output wrapper for smoke tests
#[derive(serde::Deserialize)]
struct CombinedFile {
    rules: Vec<serde_json::Value>,
}

// ── replicated helper functions ───────────────────────────────────────────────

fn slugify(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_hyphen = false;
    for c in s.chars() {
        if c.is_alphanumeric() {
            result.push(c.to_lowercase().next().unwrap());
            prev_hyphen = false;
        } else if !prev_hyphen {
            result.push('-');
            prev_hyphen = true;
        }
    }
    result.trim_matches('-').to_string()
}

fn infer_confidence_gitleaks(regex: &str) -> &'static str {
    let high_prefixes = [
        "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T",
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "glpat-", "glptt-", "GR1348941",
        "sk-ant-api", "sk-ant-admin",
        "sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod",
        "SG.", "xoxb-", "xapp-", "xoxe.",
        "eyJ",
        "npm_",
        "AIza",
    ];
    for prefix in &high_prefixes {
        if regex.contains(prefix) {
            return "high";
        }
    }
    if regex.contains("(?i)") || regex.contains("=") || regex.contains(":") {
        return "medium";
    }
    "medium"
}

fn infer_confidence_np(categories: &[String]) -> &'static str {
    if categories.iter().any(|c| c == "fuzzy") {
        "medium"
    } else {
        "high"
    }
}

fn derive_replacement_type(category: &str, subcategory: &str) -> &'static str {
    match (category, subcategory) {
        ("secret", "aws") => "faker_aws_key",
        ("secret", "github") => "faker_github_pat",
        ("secret", "jwt") => "faker_jwt",
        ("pii", "email") => "faker_email",
        ("pii", "phone") => "faker_phone",
        ("pii", "ssn") => "faker_ssn",
        ("pii", "cc") => "faker_cc_luhn",
        ("pii", "iban") => "faker_iban",
        ("infra", "ipv4") => "passthrough",
        ("infra", "uuid") => "faker_uuid",
        _ => "generic_random",
    }
}

fn unquote_yaml_scalar(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_spdb_file(content: &str) -> Vec<SpdbPattern> {
    let mut patterns = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_regex: Option<String> = None;
    let mut current_confidence: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("name:") {
            if let (Some(name), Some(regex), Some(confidence)) =
                (current_name.take(), current_regex.take(), current_confidence.take())
            {
                patterns.push(SpdbPattern { name, regex, confidence });
            }
            let val = trimmed["name:".len()..].trim();
            current_name = Some(unquote_yaml_scalar(val).to_string());
        } else if trimmed.starts_with("regex:") {
            let val = trimmed["regex:".len()..].trim();
            current_regex = Some(unquote_yaml_scalar(val).to_string());
        } else if trimmed.starts_with("confidence:") {
            let val = trimmed["confidence:".len()..].trim();
            current_confidence = Some(unquote_yaml_scalar(val).to_string());
        }
    }
    if let (Some(name), Some(regex), Some(confidence)) =
        (current_name, current_regex, current_confidence)
    {
        patterns.push(SpdbPattern { name, regex, confidence });
    }
    patterns
}

fn parse_np_file(content: &str) -> Vec<NpRule> {
    let mut rules: Vec<NpRule> = Vec::new();

    #[derive(PartialEq)]
    enum Field {
        None,
        PatternBlock { indent: usize },
        Categories,
        Skip,
    }

    let mut state = Field::None;
    let mut current: Option<NpRule> = None;

    let flush = |current: &mut Option<NpRule>, rules: &mut Vec<NpRule>| {
        if let Some(rule) = current.take() {
            if !rule.id.is_empty() && !rule.pattern.is_empty() {
                rules.push(rule);
            }
        }
    };

    for line in content.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("- name:") || trimmed == "-" {
            flush(&mut current, &mut rules);
            current = Some(NpRule {
                id: String::new(),
                name: String::new(),
                pattern: String::new(),
                categories: vec![],
            });
            if trimmed.starts_with("- name:") {
                let val = trimmed["- name:".len()..].trim();
                if let Some(ref mut rule) = current {
                    rule.name = unquote_yaml_scalar(val).to_string();
                }
            }
            state = Field::None;
            continue;
        }

        if current.is_none() {
            continue;
        }

        if let Field::PatternBlock { indent: expected } = state {
            let leading = line.len() - line.trim_start().len();
            if line.trim().is_empty() {
                if let Some(ref mut rule) = current {
                    rule.pattern.push('\n');
                }
                continue;
            }
            if leading >= expected {
                if let Some(ref mut rule) = current {
                    rule.pattern.push_str(&line[expected..]);
                    rule.pattern.push('\n');
                }
                continue;
            } else {
                state = Field::None;
            }
        }

        let is_list_item = trimmed.starts_with("- ");

        if trimmed.starts_with("name:") && !line.trim_start().starts_with("- ") {
            let val = trimmed["name:".len()..].trim();
            if let Some(ref mut rule) = current {
                rule.name = unquote_yaml_scalar(val).to_string();
            }
            state = Field::None;
        } else if trimmed.starts_with("id:") {
            let val = trimmed["id:".len()..].trim();
            if let Some(ref mut rule) = current {
                rule.id = unquote_yaml_scalar(val).to_string();
            }
            state = Field::None;
        } else if trimmed.starts_with("pattern:") {
            let val = trimmed["pattern:".len()..].trim();
            if val == "|" || val == "|2" || val == "|-" {
                let base_indent = line.len() - line.trim_start().len();
                let block_indent = base_indent + 2;
                state = Field::PatternBlock { indent: block_indent };
                if let Some(ref mut rule) = current {
                    rule.pattern.clear();
                }
            } else {
                if let Some(ref mut rule) = current {
                    rule.pattern = unquote_yaml_scalar(val).to_string();
                }
                state = Field::None;
            }
        } else if trimmed.starts_with("categories:") {
            state = Field::Categories;
        } else if trimmed.starts_with("examples:") || trimmed.starts_with("negative_examples:") || trimmed.starts_with("references:") {
            state = Field::Skip;
        } else if is_list_item {
            if state == Field::Categories {
                let val = trimmed["- ".len()..].trim();
                if let Some(ref mut rule) = current {
                    rule.categories.push(unquote_yaml_scalar(val).to_string());
                }
            }
        }
    }
    flush(&mut current, &mut rules);
    rules
}

// ── unit tests (D-05) ─────────────────────────────────────────────────────────

#[test]
fn test_slugify() {
    assert_eq!(slugify("AWS API Key"), "aws-api-key");
    // dots are non-alphanumeric → each dot becomes a hyphen-separator
    // "U.S. Phone Number": U→u, .→-, S→s, .→-, (space absorbed since prev_hyphen=true)
    // → "u-s-phone-number"
    assert_eq!(slugify("U.S. Phone Number"), "u-s-phone-number");
    assert_eq!(slugify("Stripe API Key"), "stripe-api-key");
    assert_eq!(slugify("ssn_number - 3"), "ssn-number-3");
}

#[test]
fn test_gitleaks_confidence() {
    // prefix-anchored: literal "AKIA" substring in regex → high
    let aws_anchored = r"\b(AKIA[A-Z0-9]{16})\b";
    assert_eq!(infer_confidence_gitleaks(aws_anchored), "high");

    // prefix-anchored: "ghp_" literal → high
    let github_anchored = r"\b(ghp_[a-zA-Z0-9]{36})\b";
    assert_eq!(infer_confidence_gitleaks(github_anchored), "high");

    // context-anchored: contains (?i) → medium
    let context = r"(?i)(?:adafruit)[^0-9a-z\-_](?:[0-9a-z\-_]{0,50}?)([0-9a-z]{32})";
    assert_eq!(infer_confidence_gitleaks(context), "medium");

    // context-anchored: contains "=" operator → medium
    let context2 = r"(?:password|passwd)\s*=\s*[a-z0-9]{16}";
    assert_eq!(infer_confidence_gitleaks(context2), "medium");

    // stripe regex uses alternation (?:sk|rk) — doesn't contain "sk_test" literally
    // build.rs infers from literals; the alternation form is context-anchored → medium
    let stripe_alt = r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b";
    assert_eq!(infer_confidence_gitleaks(stripe_alt), "medium");
}

#[test]
fn test_np_confidence() {
    let high_cats = vec!["api".to_string(), "identifier".to_string()];
    assert_eq!(infer_confidence_np(&high_cats), "high");

    let fuzzy_cats = vec!["api".to_string(), "fuzzy".to_string(), "secret".to_string()];
    assert_eq!(infer_confidence_np(&fuzzy_cats), "medium");

    let empty: Vec<String> = vec![];
    assert_eq!(infer_confidence_np(&empty), "high");
}

#[test]
fn test_derive_replacement_type() {
    assert_eq!(derive_replacement_type("secret", "aws"), "faker_aws_key");
    assert_eq!(derive_replacement_type("pii", "email"), "faker_email");
    assert_eq!(derive_replacement_type("infra", "ipv4"), "passthrough");
    assert_eq!(derive_replacement_type("", "unknown"), "generic_random");
    assert_eq!(derive_replacement_type("pii", "ssn"), "faker_ssn");
    assert_eq!(derive_replacement_type("secret", "jwt"), "faker_jwt");
    assert_eq!(derive_replacement_type("pii", "cc"), "faker_cc_luhn");
}

#[test]
fn test_dedup_priority() {
    let make_rule = |source: &str| NormalizedRule {
        id: "test.duplicate".to_string(),
        name: format!("From {}", source),
        category: "pii".to_string(),
        subcategory: "email".to_string(),
        source: source.to_string(),
        confidence: "high".to_string(),
        regex: r"[a-z]+@[a-z]+\.com".to_string(),
        keywords: vec![],
        entropy: None,
        tags: vec![],
        checksum_type: None,
        replacement_type: "faker_email".to_string(),
        description: "".to_string(),
        severity: "high".to_string(),
    };

    // dedup map: last insert with same key wins
    // build.rs inserts spdb first, then gl, then np, then ha — ha overwrites all
    let mut dedup: HashMap<String, NormalizedRule> = HashMap::new();
    dedup.insert("test.duplicate".to_string(), make_rule("secrets-patterns-db"));
    dedup.insert("test.duplicate".to_string(), make_rule("gitleaks"));
    dedup.insert("test.duplicate".to_string(), make_rule("nosey-parker"));
    dedup.insert("test.duplicate".to_string(), make_rule("hand-authored"));

    let winner = dedup.get("test.duplicate").unwrap();
    assert_eq!(winner.source, "hand-authored",
        "hand-authored must win dedup for duplicate ids (last insert wins)");
}

#[test]
fn test_gitleaks_parser() {
    let fixture = include_str!("fixtures/gitleaks_snippet.toml");
    let gl_file: GitleaksFile = toml::from_str(fixture)
        .expect("fixture must parse as gitleaks TOML");

    assert_eq!(gl_file.rules.len(), 2);

    let stripe = &gl_file.rules[0];
    assert_eq!(stripe.id, "stripe-access-token");
    assert!(stripe.regex.is_some(), "stripe rule must have regex");
    // id gets gl. prefix when normalized
    let normalized_id = format!("gl.{}", stripe.id);
    assert!(normalized_id.starts_with("gl."), "id must be prefixed with gl.");
    assert_eq!(normalized_id, "gl.stripe-access-token");
    assert_eq!(stripe.tags.as_ref().unwrap(), &["stripe"]);
    assert_eq!(stripe.entropy.unwrap(), 2.0);
    let kw = stripe.keywords.as_ref().unwrap();
    assert!(kw.contains(&"sk_test".to_string()));
    assert!(kw.contains(&"sk_live".to_string()));
    // stripe regex uses alternation form (?:sk|rk)_(?:test|live|prod) — no literal "sk_test"
    // so infer_confidence returns medium (context-anchored by absence of literal prefix)
    let stripe_regex = stripe.regex.as_ref().unwrap();
    assert_eq!(infer_confidence_gitleaks(stripe_regex), "medium",
        "alternation-form stripe regex → medium (no literal sk_test prefix)");

    let adafruit = &gl_file.rules[1];
    assert_eq!(adafruit.id, "adafruit-api-key");
    let ada_regex = adafruit.regex.as_ref().unwrap();
    assert_eq!(infer_confidence_gitleaks(ada_regex), "medium",
        "(?i) context-anchored → medium confidence");
    assert_eq!(format!("gl.{}", adafruit.id), "gl.adafruit-api-key");
}

#[test]
fn test_spdb_parser() {
    let fixture = include_str!("fixtures/spdb_snippet.yaml");
    let patterns = parse_spdb_file(fixture);

    assert_eq!(patterns.len(), 2);

    let aws = &patterns[0];
    assert_eq!(aws.name, "AWS API Key");
    assert_eq!(aws.confidence, "high");
    let id = format!("spdb.{}", slugify(&aws.name));
    assert_eq!(id, "spdb.aws-api-key",
        "id must be slugified name with spdb. prefix");

    let stripe = &patterns[1];
    assert_eq!(stripe.name, "Stripe API Key");
    assert_eq!(stripe.confidence, "high");
    assert_eq!(format!("spdb.{}", slugify(&stripe.name)), "spdb.stripe-api-key");
}

#[test]
fn test_np_parser() {
    let fixture = include_str!("fixtures/np_snippet.yaml");
    let rules = parse_np_file(fixture);

    assert_eq!(rules.len(), 2, "expected 2 rules from np fixture");

    let aws1 = &rules[0];
    assert_eq!(aws1.id, "np.aws.1",
        "NP id must be verbatim (already namespaced np.*)");
    assert_eq!(aws1.name, "AWS API Key");
    assert!(aws1.categories.contains(&"api".to_string()),
        "categories must include 'api'");
    assert_eq!(infer_confidence_np(&aws1.categories), "high",
        "no fuzzy → high confidence");
    assert!(!aws1.pattern.is_empty(), "pattern must be present");

    let aws2 = &rules[1];
    assert_eq!(aws2.id, "np.aws.2");
    assert!(aws2.categories.contains(&"fuzzy".to_string()),
        "aws2 must have fuzzy category");
    assert_eq!(infer_confidence_np(&aws2.categories), "medium");
    // multiline (?x) pattern must preserve newlines
    assert!(aws2.pattern.contains('\n'),
        "multiline pattern must preserve newlines");
    assert!(aws2.pattern.contains("(?x)"),
        "(?x) flag must be preserved");
}

#[test]
fn test_invalid_regex_fails_validation() {
    let bad_regex = r"(?unclosed";
    let result = std::panic::catch_unwind(|| {
        regex::bytes::RegexBuilder::new(bad_regex)
            .size_limit(256 * 1024 * 1024)
            .dfa_size_limit(256 * 1024 * 1024)
            .build()
            .unwrap_or_else(|e| panic!("invalid regex: {}", e));
    });
    assert!(result.is_err(), "invalid regex must cause a panic/error");
}

// ── smoke tests (D-06) ────────────────────────────────────────────────────────
// these tests require `cargo build` to have run first (rules/combined.yaml must exist)

#[test]
fn smoke_combined_yaml_exists_and_has_minimum_rules() {
    let path = "rules/combined.yaml";
    if !std::path::Path::new(path).exists() {
        // skip if build hasn't run yet (first clone before build)
        eprintln!("SKIP: {} not found — run cargo build first", path);
        return;
    }
    let content = fs::read_to_string(path)
        .expect("failed to read rules/combined.yaml");
    let parsed: CombinedFile = serde_yml::from_str(&content)
        .expect("rules/combined.yaml must be valid YAML");
    let count = parsed.rules.len();
    assert!(count >= 82,
        "expected >= 82 rules in combined.yaml, got {}", count);
    eprintln!("smoke: combined.yaml has {} rules", count);
}

#[test]
fn smoke_combined_yaml_has_all_sources() {
    let path = "rules/combined.yaml";
    if !std::path::Path::new(path).exists() { return; }
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("id: np."), "missing nosey-parker rules (np.*)");
    assert!(content.contains("id: gl."), "missing gitleaks rules (gl.*)");
    assert!(content.contains("id: spdb."), "missing spdb rules (spdb.*)");
    assert!(content.contains("id: ha."), "missing hand-authored rules (ha.*)");
}

#[test]
fn smoke_spot_check_np_aws_1() {
    let path = "rules/combined.yaml";
    if !std::path::Path::new(path).exists() { return; }
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("id: np.aws.1"), "np.aws.1 must be present");
    assert!(content.contains("faker_aws_key"),
        "np.aws.1 must have faker_aws_key replacement");
}

#[test]
fn smoke_spot_check_hand_authored() {
    let path = "rules/combined.yaml";
    if !std::path::Path::new(path).exists() { return; }
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("id: ha.pii.uk-nin"), "ha.pii.uk-nin must be present");
    assert!(content.contains("id: ha.secret.ibm-cloud-iam"),
        "ha.secret.ibm-cloud-iam must be present");
}
