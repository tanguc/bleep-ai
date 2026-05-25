use serde::{Deserialize, Serialize};

/// confidence level for a detection rule
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

/// top-level taxonomy category
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
    Pii,
    Infra,
}

/// checksum algorithm applied post-match
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumType {
    Luhn,
}

/// fake data strategy used during replacement
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementType {
    FakerEmail,
    FakerPhone,
    FakerSsn,
    FakerCcLuhn,
    FakerIban,
    FakerUuid,
    FakerIpv4,
    FakerAwsKey,
    FakerGithubPat,
    FakerJwt,
    FakerApiKey,
    FakerDbConn,
    FakerUrlCred,
    FpeNumeric,
    GenericRandom,
    Passthrough,
}

impl Default for ReplacementType {
    fn default() -> Self {
        ReplacementType::GenericRandom
    }
}

/// canonical normalized rule — output of build.rs normalization pipeline
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NormalizedRule {
    // required fields
    pub id: String,
    pub name: String,
    pub category: Category,
    pub subcategory: String,
    pub regex: String,
    pub source: String,

    // optional fields with defaults
    #[serde(default)]
    pub confidence: Confidence,

    #[serde(default)]
    pub entropy: Option<f64>,

    #[serde(default)]
    pub keywords: Vec<String>,

    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default)]
    pub checksum_type: Option<ChecksumType>,

    #[serde(default)]
    pub replacement_type: ReplacementType,

    #[serde(default)]
    pub description: String,

    #[serde(default = "default_severity")]
    pub severity: String,

    /// Literal prefix extracted from `regex` at build time (e.g. `hf_`, `AKIA`,
    /// `sk-ant-api`). When present, realistic replacers preserve these bytes
    /// verbatim so the substituted token still looks like the same vendor's
    /// secret format. Populated by the build-rules pipeline; `None` when no
    /// stable literal head exists (e.g. alternation, leading char class).
    #[serde(default)]
    pub literal_prefix: Option<String>,
}

fn default_severity() -> String {
    "medium".to_string()
}

/// derive replacement type from category + subcategory — 28-row lookup table
/// from docs/arch/BUILD-PIPELINE.md section 4
pub fn derive_replacement_type(category: &str, subcategory: &str) -> ReplacementType {
    match (category, subcategory) {
        ("secret", "aws") => ReplacementType::FakerAwsKey,
        ("secret", "github") => ReplacementType::FakerGithubPat,
        ("secret", "gitlab") => ReplacementType::FakerApiKey,
        ("secret", "stripe") => ReplacementType::FakerApiKey,
        ("secret", "sendgrid") => ReplacementType::FakerApiKey,
        ("secret", "slack") => ReplacementType::FakerApiKey,
        ("secret", "openai") => ReplacementType::FakerApiKey,
        ("secret", "anthropic") => ReplacementType::FakerApiKey,
        ("secret", "jwt") => ReplacementType::FakerJwt,
        ("secret", "private-key") => ReplacementType::FakerApiKey,
        ("secret", "db-conn") => ReplacementType::FakerDbConn,
        ("secret", "url-cred") => ReplacementType::FakerUrlCred,
        ("secret", "npm") => ReplacementType::FakerApiKey,
        ("secret", "pypi") => ReplacementType::FakerApiKey,
        ("secret", "telegram") => ReplacementType::FakerApiKey,
        ("secret", "generic") => ReplacementType::FakerApiKey,
        ("pii", "email") => ReplacementType::FakerEmail,
        ("pii", "phone") => ReplacementType::FakerPhone,
        ("pii", "ssn") => ReplacementType::FakerSsn,
        ("pii", "cc") => ReplacementType::FakerCcLuhn,
        ("pii", "iban") => ReplacementType::FakerIban,
        ("pii", "uk-nin") => ReplacementType::GenericRandom,
        ("pii", "pl-pesel") => ReplacementType::GenericRandom,
        ("pii", "fr-insee") => ReplacementType::GenericRandom,
        ("pii", "de-taxid") => ReplacementType::GenericRandom,
        ("pii", "address") => ReplacementType::GenericRandom,
        ("infra", "ipv4") => ReplacementType::Passthrough,
        ("infra", "uuid") => ReplacementType::FakerUuid,
        ("infra", "url-cred") => ReplacementType::FakerUrlCred,
        _ => ReplacementType::GenericRandom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replacement_type_count() {
        // verify all 16 variants are accessible
        let variants = [
            ReplacementType::FakerEmail,
            ReplacementType::FakerPhone,
            ReplacementType::FakerSsn,
            ReplacementType::FakerCcLuhn,
            ReplacementType::FakerIban,
            ReplacementType::FakerUuid,
            ReplacementType::FakerIpv4,
            ReplacementType::FakerAwsKey,
            ReplacementType::FakerGithubPat,
            ReplacementType::FakerJwt,
            ReplacementType::FakerApiKey,
            ReplacementType::FakerDbConn,
            ReplacementType::FakerUrlCred,
            ReplacementType::FpeNumeric,
            ReplacementType::GenericRandom,
            ReplacementType::Passthrough,
        ];
        assert_eq!(variants.len(), 16);
    }

    #[test]
    fn test_derive_replacement_type_known_pairs() {
        assert_eq!(derive_replacement_type("secret", "aws"), ReplacementType::FakerAwsKey);
        assert_eq!(derive_replacement_type("secret", "github"), ReplacementType::FakerGithubPat);
        assert_eq!(derive_replacement_type("secret", "jwt"), ReplacementType::FakerJwt);
        assert_eq!(derive_replacement_type("pii", "email"), ReplacementType::FakerEmail);
        assert_eq!(derive_replacement_type("pii", "ssn"), ReplacementType::FakerSsn);
        assert_eq!(derive_replacement_type("infra", "ipv4"), ReplacementType::Passthrough);
        assert_eq!(derive_replacement_type("infra", "uuid"), ReplacementType::FakerUuid);
    }

    #[test]
    fn test_derive_replacement_type_fallback() {
        assert_eq!(derive_replacement_type("unknown", "unknown"), ReplacementType::GenericRandom);
        assert_eq!(derive_replacement_type("pii", "uk-nin"), ReplacementType::GenericRandom);
    }

    #[test]
    fn test_normalized_rule_defaults() {
        let yaml = r#"
id: test.rule.1
name: Test Rule
category: secret
subcategory: generic
regex: '\btest\b'
source: hand-authored
"#;
        let rule: NormalizedRule = serde_yml::from_str(yaml).expect("should parse");
        assert_eq!(rule.confidence, Confidence::Medium);
        assert_eq!(rule.entropy, None);
        assert!(rule.keywords.is_empty());
        assert!(rule.tags.is_empty());
        assert_eq!(rule.checksum_type, None);
        assert_eq!(rule.replacement_type, ReplacementType::GenericRandom);
        assert_eq!(rule.description, "");
        assert_eq!(rule.severity, "medium");
    }
}
