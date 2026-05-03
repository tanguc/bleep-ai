//! Rule normalization pipeline.
//!
//! Reads vendor sources from `rules/vendor/`, normalizes to the internal schema,
//! deduplicates, validates, and writes `rules/combined.yaml` +
//! `rules/patterns-test-fixtures.yaml`.
//!
//! Run via the `build-rules` binary (`cargo run --bin build-rules`) or directly via
//! [`run`].

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Options controlling the pipeline run.
#[derive(Debug, Default, Clone)]
pub struct RunOptions {
    /// If `Some(n)`, truncate the final ruleset to `n` rules (dev iteration).
    pub max_rules: Option<usize>,
    /// If `true`, suppress the `eprintln!` progress output.
    pub quiet: bool,
}

/// Summary of what the pipeline produced.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub gitleaks_rules: usize,
    pub spdb_rules: usize,
    pub np_rules: usize,
    pub ha_rules: usize,
    pub total_rules: usize,
    pub combined_path: String,
    pub fixtures_path: String,
}

macro_rules! log_progress {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            eprintln!($($arg)*);
        }
    };
}

// ── vendor parsing structs ─────────────────────────────────────────────────────

// gitleaks TOML: [[rules]] array
#[derive(serde::Deserialize)]
struct GitleaksFile {
    rules: Vec<GitleaksRule>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct GitleaksRule {
    id: String,
    description: Option<String>,
    // regex is optional — some rules use only `path` (file path matching)
    regex: Option<String>,
    entropy: Option<f64>,
    keywords: Option<Vec<String>>,
    tags: Option<Vec<String>>,
}

// secrets-patterns-db is parsed with a line-by-line parser because serde_yml / libyml
// has a known panic on large YAML files with long unquoted scalars (libyml "String join
// would overflow memory bounds" in yaml_parser_scan_flow_scalar).
// The SPDB file has a rigid 4-line repeating structure that makes a hand-rolled parser safe.
struct SpdbPattern {
    name: String,
    regex: String,
    confidence: String,
}

// Nosey Parker rules are parsed with a custom state machine (serde_yml / libyml panics
// on NP files that contain very long single-line example strings — e.g., pem.yml has
// base64-encoded private key examples that are 2000+ chars per line).
struct NpRule {
    id: String,
    name: String,
    pattern: String,
    categories: Vec<String>,
    examples: Vec<String>,
    negative_examples: Vec<String>,
}

// exclusions file
#[derive(serde::Deserialize)]
struct Exclusions {
    excluded: Vec<String>,
}

// hand-authored input uses same NormalizedRule struct
#[derive(serde::Deserialize)]
struct HandAuthoredFile {
    rules: Vec<NormalizedRule>,
}

// test fixtures output struct
#[derive(serde::Serialize)]
struct TestFixturesFile {
    fixtures: Vec<TestFixture>,
}

#[derive(serde::Serialize)]
struct TestFixture {
    id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    examples: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    negative_examples: Vec<String>,
}

// ── output struct — mirrors src/types/rule.rs but uses String for enum fields ─

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

// ── combined output wrapper ────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct CombinedFile<'a> {
    rules: &'a [NormalizedRule],
}

// ── helper functions ───────────────────────────────────────────────────────────

/// strip POSIX-style inline comments (?# ... ) from a regex string
/// the Rust regex crate does not support (?# ...) comment syntax — only (?x) # line comments
/// these appear in NP patterns inside (?x) verbose blocks
fn strip_posix_comments(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // look for (?# ... ) comment blocks
        if i + 2 < bytes.len() && bytes[i] == b'(' && bytes[i + 1] == b'?' && bytes[i + 2] == b'#' {
            // find the closing ')'
            let start = i;
            i += 3;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth -= 1;
                }
                i += 1;
            }
            // replace comment with empty string (preserve surrounding whitespace for (?x) mode)
            let _ = start;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// slugify: lowercase, replace non-alphanumeric (except hyphen) with hyphen,
/// collapse consecutive hyphens, strip leading/trailing hyphens
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
    // strip leading/trailing hyphens
    result.trim_matches('-').to_string()
}

/// infer confidence for a gitleaks rule based on regex structure
fn infer_confidence_gitleaks(regex: &str) -> &'static str {
    // tier 1 HIGH: prefix-anchored — starts with or contains a known vendor-specific literal
    let high_prefixes = [
        "AKIA",
        "AGPA",
        "AIDA",
        "AROA",
        "AIPA",
        "ANPA",
        "ANVA",
        "ASIA",
        "A3T",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "glptt-",
        "GR1348941",
        "sk-ant-api",
        "sk-ant-admin",
        "sk_test",
        "sk_live",
        "sk_prod",
        "rk_test",
        "rk_live",
        "rk_prod",
        "SG.",
        "xoxb-",
        "xapp-",
        "xoxe.",
        "ops_eyJ",
        "AGE-SECRET-KEY-1",
        "A3-",
        "eyJ",
        "pypi-AgEI",
        "pypi-AgEN",
        "npm_",
        "dapi",
        "dp.pt.",
        "pscale_tkn_",
        "pscale_oauth_",
        "pscale_pw_",
        "PMAK-",
        "NRAK-",
        "NRJS-",
        "AIza",
        "glc_",
        "glsa_",
        "hf_",
        "api_org_",
        "dop_v1_",
        "LTAI",
        "CLOJARS_",
        "dnkey-",
        "AKC",
        "fo1_",
        "fio-u-",
        "FLWSECK",
        "FLWPUBK",
        "pplx-",
        "pnu_",
        "sgp_",
        "shpat_",
        "shpca_",
        "shppa_",
        "shpss_",
        "squ_",
        "tfp_",
        "rdme_",
        "rubygems_",
        "tk-us-",
        "ico-",
        "lin_api_",
        "hubspot",
        "pat-",
        "EZAK",
        "EZTK",
        "xkeysib-",
        "hvs.",
        "b.",
        "yandex",
        "y1_",
        "AQVN",
        "YCA",
        "xoxp-",
        "xoxa-",
        "ACC_",
        "acc_",
    ];
    for prefix in &high_prefixes {
        if regex.contains(prefix) {
            return "high";
        }
    }
    // tier 2 MEDIUM: context-anchored — contains assignment operators or keyword structure
    if regex.contains("(?i)") || regex.contains("=") || regex.contains(":") || regex.contains("=>")
    {
        return "medium";
    }
    // default medium (log warning is handled by caller)
    "medium"
}

/// infer confidence for a nosey-parker rule
fn infer_confidence_np(categories: &[String]) -> &'static str {
    if categories.iter().any(|c| c == "fuzzy") {
        "medium"
    } else {
        "high"
    }
}

/// derive replacement type from category + subcategory — 28-row lookup table
fn derive_replacement_type(category: &str, subcategory: &str) -> &'static str {
    match (category, subcategory) {
        ("secret", "aws") => "faker_aws_key",
        ("secret", "github") => "faker_github_pat",
        ("secret", "gitlab") => "faker_api_key",
        ("secret", "stripe") => "faker_api_key",
        ("secret", "sendgrid") => "faker_api_key",
        ("secret", "slack") => "faker_api_key",
        ("secret", "openai") => "faker_api_key",
        ("secret", "anthropic") => "faker_api_key",
        ("secret", "jwt") => "faker_jwt",
        ("secret", "private-key") => "faker_api_key",
        ("secret", "db-conn") => "faker_db_conn",
        ("secret", "url-cred") => "faker_url_cred",
        ("secret", "npm") => "faker_api_key",
        ("secret", "pypi") => "faker_api_key",
        ("secret", "telegram") => "faker_api_key",
        ("secret", "generic") => "faker_api_key",
        ("pii", "email") => "faker_email",
        ("pii", "phone") => "faker_phone",
        ("pii", "ssn") => "faker_ssn",
        ("pii", "cc") => "faker_cc_luhn",
        ("pii", "iban") => "faker_iban",
        ("pii", "uk-nin") => "generic_random",
        ("pii", "pl-pesel") => "generic_random",
        ("pii", "fr-insee") => "generic_random",
        ("pii", "de-taxid") => "generic_random",
        ("pii", "address") => "generic_random",
        ("infra", "ipv4") => "passthrough",
        ("infra", "uuid") => "faker_uuid",
        ("infra", "url-cred") => "faker_url_cred",
        _ => "generic_random",
    }
}

/// derive severity from confidence
fn derive_severity(confidence: &str) -> &'static str {
    if confidence == "high" {
        "high"
    } else {
        "medium"
    }
}

/// lookup (category, subcategory) for a gitleaks rule id
fn gl_subcategory(id: &str) -> (&'static str, &'static str) {
    match id {
        // aws
        "aws-amazon-bedrock-api-key-long-lived" => ("secret", "aws"),
        "aws-amazon-bedrock-api-key-short-lived" => ("secret", "aws"),
        // anthropic
        "anthropic-admin-api-key" => ("secret", "anthropic"),
        // openai
        "openai-api-key" => ("secret", "openai"),
        // github
        "github-fine-grained-pat" => ("secret", "github"),
        // gitlab
        "gitlab-ptt" => ("secret", "gitlab"),
        "gitlab-rrt" => ("secret", "gitlab"),
        "gitlab-pat-routable" => ("secret", "gitlab"),
        "gitlab-cicd-job-token" => ("secret", "gitlab"),
        "gitlab-deploy-token" => ("secret", "gitlab"),
        "gitlab-feed-token" => ("secret", "gitlab"),
        "gitlab-incoming-mail-token" => ("secret", "gitlab"),
        "gitlab-kubernetes-agent-token" => ("secret", "gitlab"),
        "gitlab-oauth-app-secret" => ("secret", "gitlab"),
        "gitlab-runner-authentication-token" => ("secret", "gitlab"),
        "gitlab-scim-token" => ("secret", "gitlab"),
        "gitlab-session-cookie" => ("secret", "gitlab"),
        // stripe
        "stripe-access-token" => ("secret", "stripe"),
        // slack
        "slack-app-token" => ("secret", "slack"),
        "slack-config-access-token" => ("secret", "slack"),
        "slack-config-refresh-token" => ("secret", "slack"),
        "slack-legacy-bot-token" => ("secret", "slack"),
        "slack-legacy-token" => ("secret", "slack"),
        "slack-legacy-workspace-token" => ("secret", "slack"),
        "slack-user-token" => ("secret", "slack"),
        "slack-webhook-url" => ("secret", "slack"),
        // jwt
        "jwt-base64" => ("secret", "jwt"),
        // private-key
        "private-key" => ("secret", "private-key"),
        "pkcs12-file" => ("secret", "private-key"),
        // sendgrid
        "sendgrid-api-token" => ("secret", "sendgrid"),
        // mailchimp
        "mailchimp-api-key" => ("secret", "generic"),
        // npm
        "npm-access-token" => ("secret", "npm"),
        // pypi
        "pypi-upload-token" => ("secret", "pypi"),
        // telegram
        "telegram-bot-api-token" => ("secret", "telegram"),
        // twilio
        "twilio-api-key" => ("secret", "generic"),
        // discord
        "discord-api-token" => ("secret", "generic"),
        "discord-client-id" => ("secret", "generic"),
        "discord-client-secret" => ("secret", "generic"),
        // artifactory / jfrog
        "artifactory-api-key" => ("secret", "generic"),
        "artifactory-reference-token" => ("secret", "generic"),
        "jfrog-api-key" => ("secret", "generic"),
        "jfrog-identity-token" => ("secret", "generic"),
        // azure
        "azure-ad-client-secret" => ("secret", "generic"),
        // square
        "square-access-token" => ("secret", "generic"),
        "squarespace-access-token" => ("secret", "generic"),
        // kubernetes / infra
        "kubernetes-secret-yaml" => ("infra", "generic"),
        // various saas
        "1password-secret-key" => ("secret", "generic"),
        "1password-service-account-token" => ("secret", "generic"),
        "age-secret-key" => ("secret", "private-key"),
        "airtable-api-key" => ("secret", "generic"),
        "airtable-personnal-access-token" => ("secret", "generic"),
        "algolia-api-key" => ("secret", "generic"),
        "alibaba-access-key-id" => ("secret", "generic"),
        "alibaba-secret-key" => ("secret", "generic"),
        "asana-client-id" => ("secret", "generic"),
        "asana-client-secret" => ("secret", "generic"),
        "atlassian-api-token" => ("secret", "generic"),
        "authress-service-client-access-key" => ("secret", "generic"),
        "bitbucket-client-id" => ("secret", "generic"),
        "bitbucket-client-secret" => ("secret", "generic"),
        "bittrex-access-key" => ("secret", "generic"),
        "bittrex-secret-key" => ("secret", "generic"),
        "cisco-meraki-api-key" => ("secret", "generic"),
        "clickhouse-cloud-api-secret-key" => ("secret", "generic"),
        "clojars-api-token" => ("secret", "generic"),
        "cloudflare-api-key" => ("secret", "generic"),
        "cloudflare-global-api-key" => ("secret", "generic"),
        "cloudflare-origin-ca-key" => ("secret", "generic"),
        "codecov-access-token" => ("secret", "generic"),
        "cohere-api-token" => ("secret", "generic"),
        "coinbase-access-token" => ("secret", "generic"),
        "confluent-access-token" => ("secret", "generic"),
        "confluent-secret-key" => ("secret", "generic"),
        "contentful-delivery-api-token" => ("secret", "generic"),
        "databricks-api-token" => ("secret", "generic"),
        "datadog-access-token" => ("secret", "generic"),
        "defined-networking-api-token" => ("secret", "generic"),
        "digitalocean-access-token" => ("secret", "generic"),
        "digitalocean-pat" => ("secret", "generic"),
        "digitalocean-refresh-token" => ("secret", "generic"),
        "doppler-api-token" => ("secret", "generic"),
        "droneci-access-token" => ("secret", "generic"),
        "dropbox-api-token" => ("secret", "generic"),
        "dropbox-long-lived-api-token" => ("secret", "generic"),
        "dropbox-short-lived-api-token" => ("secret", "generic"),
        "duffel-api-token" => ("secret", "generic"),
        "dynatrace-api-token" => ("secret", "generic"),
        "easypost-api-token" => ("secret", "generic"),
        "easypost-test-api-token" => ("secret", "generic"),
        "etsy-access-token" => ("secret", "generic"),
        "facebook-access-token" => ("secret", "generic"),
        "facebook-page-access-token" => ("secret", "generic"),
        "facebook-secret" => ("secret", "generic"),
        "fastly-api-token" => ("secret", "generic"),
        "finicity-api-token" => ("secret", "generic"),
        "finicity-client-secret" => ("secret", "generic"),
        "finnhub-access-token" => ("secret", "generic"),
        "flickr-access-token" => ("secret", "generic"),
        "flutterwave-encryption-key" => ("secret", "generic"),
        "flutterwave-public-key" => ("secret", "generic"),
        "flutterwave-secret-key" => ("secret", "generic"),
        "flyio-access-token" => ("secret", "generic"),
        "frameio-api-token" => ("secret", "generic"),
        "freemius-secret-key" => ("secret", "generic"),
        "freshbooks-access-token" => ("secret", "generic"),
        "gcp-api-key" => ("secret", "generic"),
        "gitter-access-token" => ("secret", "generic"),
        "gocardless-api-token" => ("secret", "generic"),
        "grafana-api-key" => ("secret", "generic"),
        "grafana-cloud-api-token" => ("secret", "generic"),
        "grafana-service-account-token" => ("secret", "generic"),
        "harness-api-key" => ("secret", "generic"),
        "hashicorp-tf-api-token" => ("secret", "generic"),
        "hashicorp-tf-password" => ("secret", "generic"),
        "heroku-api-key" => ("secret", "generic"),
        "heroku-api-key-v2" => ("secret", "generic"),
        "hubspot-api-key" => ("secret", "generic"),
        "huggingface-access-token" => ("secret", "generic"),
        "huggingface-organization-api-token" => ("secret", "generic"),
        "infracost-api-token" => ("secret", "generic"),
        "intercom-api-key" => ("secret", "generic"),
        "intra42-client-secret" => ("secret", "generic"),
        "kraken-access-token" => ("secret", "generic"),
        "kucoin-access-token" => ("secret", "generic"),
        "kucoin-secret-key" => ("secret", "generic"),
        "launchdarkly-access-token" => ("secret", "generic"),
        "linear-api-key" => ("secret", "generic"),
        "linear-client-secret" => ("secret", "generic"),
        "linkedin-client-id" => ("secret", "generic"),
        "linkedin-client-secret" => ("secret", "generic"),
        "lob-api-key" => ("secret", "generic"),
        "lob-pub-api-key" => ("secret", "generic"),
        "looker-client-id" => ("secret", "generic"),
        "looker-client-secret" => ("secret", "generic"),
        "mailgun-private-api-token" => ("secret", "generic"),
        "mailgun-pub-key" => ("secret", "generic"),
        "mailgun-signing-key" => ("secret", "generic"),
        "mapbox-api-token" => ("secret", "generic"),
        "mattermost-access-token" => ("secret", "generic"),
        "maxmind-license-key" => ("secret", "generic"),
        "messagebird-api-token" => ("secret", "generic"),
        "messagebird-client-id" => ("secret", "generic"),
        "microsoft-teams-webhook" => ("secret", "generic"),
        "netlify-access-token" => ("secret", "generic"),
        "new-relic-browser-api-token" => ("secret", "generic"),
        "new-relic-insert-key" => ("secret", "generic"),
        "new-relic-user-api-id" => ("secret", "generic"),
        "new-relic-user-api-key" => ("secret", "generic"),
        "notion-api-token" => ("secret", "generic"),
        "nuget-config-password" => ("secret", "generic"),
        "nytimes-access-token" => ("secret", "generic"),
        "octopus-deploy-api-key" => ("secret", "generic"),
        "okta-access-token" => ("secret", "generic"),
        "openshift-user-token" => ("secret", "generic"),
        "perplexity-api-key" => ("secret", "generic"),
        "plaid-api-token" => ("secret", "generic"),
        "plaid-client-id" => ("secret", "generic"),
        "plaid-secret-key" => ("secret", "generic"),
        "planetscale-api-token" => ("secret", "generic"),
        "planetscale-oauth-token" => ("secret", "generic"),
        "planetscale-password" => ("secret", "generic"),
        "postman-api-token" => ("secret", "generic"),
        "prefect-api-token" => ("secret", "generic"),
        "privateai-api-token" => ("secret", "generic"),
        "pulumi-api-token" => ("secret", "generic"),
        "rapidapi-access-token" => ("secret", "generic"),
        "readme-api-token" => ("secret", "generic"),
        "rubygems-api-token" => ("secret", "generic"),
        "scalingo-api-token" => ("secret", "generic"),
        "sendbird-access-id" => ("secret", "generic"),
        "sendbird-access-token" => ("secret", "generic"),
        "sendinblue-api-token" => ("secret", "generic"),
        "sentry-access-token" => ("secret", "generic"),
        "sentry-org-token" => ("secret", "generic"),
        "sentry-user-token" => ("secret", "generic"),
        "settlemint-application-access-token" => ("secret", "generic"),
        "settlemint-personal-access-token" => ("secret", "generic"),
        "settlemint-service-access-token" => ("secret", "generic"),
        "shippo-api-token" => ("secret", "generic"),
        "shopify-access-token" => ("secret", "generic"),
        "shopify-custom-access-token" => ("secret", "generic"),
        "shopify-private-app-access-token" => ("secret", "generic"),
        "shopify-shared-secret" => ("secret", "generic"),
        "sidekiq-secret" => ("secret", "generic"),
        "sidekiq-sensitive-url" => ("secret", "db-conn"),
        "snyk-api-token" => ("secret", "generic"),
        "sonar-api-token" => ("secret", "generic"),
        "sourcegraph-access-token" => ("secret", "generic"),
        "sumologic-access-id" => ("secret", "generic"),
        "sumologic-access-token" => ("secret", "generic"),
        "travisci-access-token" => ("secret", "generic"),
        "twitch-api-token" => ("secret", "generic"),
        "twitter-access-secret" => ("secret", "generic"),
        "twitter-access-token" => ("secret", "generic"),
        "twitter-api-key" => ("secret", "generic"),
        "twitter-api-secret" => ("secret", "generic"),
        "twitter-bearer-token" => ("secret", "generic"),
        "typeform-api-token" => ("secret", "generic"),
        "vault-batch-token" => ("secret", "generic"),
        "vault-service-token" => ("secret", "generic"),
        "yandex-access-token" => ("secret", "generic"),
        "yandex-api-key" => ("secret", "generic"),
        "yandex-aws-access-token" => ("secret", "generic"),
        "zendesk-secret-key" => ("secret", "generic"),
        // detect-secrets sourced (included via gitleaks equivalent or standalone)
        "npm" => ("secret", "npm"),
        "pypi_token-test" => ("secret", "pypi"),
        "Azure Storage Key" => ("secret", "generic"),
        "Cloudant URL" => ("secret", "db-conn"),
        "ibm_cos_hmac" => ("secret", "generic"),
        "Softlayer URL" => ("secret", "generic"),
        _ => {
            eprintln!(
                "rule_pipeline: warn: unknown gitleaks id '{}' — defaulting to (secret, generic)",
                id
            );
            ("secret", "generic")
        }
    }
}

/// lookup (category, subcategory) for a nosey-parker rule id
fn np_subcategory(id: &str) -> (&'static str, &'static str) {
    match id {
        "np.aws.1" | "np.aws.2" => ("secret", "aws"),
        "np.anthropic.1" => ("secret", "anthropic"),
        "np.github.1" | "np.github.2" | "np.github.3" | "np.github.4" => ("secret", "github"),
        "np.gitlab.1" => ("secret", "gitlab"),
        "np.slack.2" => ("secret", "slack"),
        "np.jwt.1" => ("secret", "jwt"),
        "np.postgres.1" => ("secret", "db-conn"),
        "np.mongo.1" => ("secret", "db-conn"),
        "np.odbc.1" => ("secret", "db-conn"),
        "np.http.1" => ("infra", "url-cred"),
        // other NP ids — infer from id prefix
        id if id.starts_with("np.aws.") => ("secret", "aws"),
        id if id.starts_with("np.anthropic.") => ("secret", "anthropic"),
        id if id.starts_with("np.github.") => ("secret", "github"),
        id if id.starts_with("np.gitlab.") => ("secret", "gitlab"),
        id if id.starts_with("np.slack.") => ("secret", "slack"),
        id if id.starts_with("np.jwt.") => ("secret", "jwt"),
        id if id.starts_with("np.stripe.") => ("secret", "stripe"),
        id if id.starts_with("np.openai.") => ("secret", "openai"),
        id if id.starts_with("np.postgres.")
            || id.starts_with("np.mongo.")
            || id.starts_with("np.odbc.") =>
        {
            ("secret", "db-conn")
        }
        id if id.starts_with("np.http.") => ("infra", "url-cred"),
        id if id.starts_with("np.pem.") => ("secret", "private-key"),
        _ => {
            eprintln!(
                "rule_pipeline: warn: unknown NP id '{}' — defaulting to (secret, generic)",
                id
            );
            ("secret", "generic")
        }
    }
}

/// derive subcategory from spdb pattern name
fn spdb_subcategory(name: &str, category: &str) -> &'static str {
    let name_lower = name.to_lowercase();
    if category == "pii" {
        if name_lower.contains("ssn") || name_lower.contains("social security") {
            return "ssn";
        }
        if name_lower.contains("email") {
            return "email";
        }
        if name_lower.contains("phone") {
            return "phone";
        }
        if name_lower.contains("visa")
            || name_lower.contains("mastercard")
            || name_lower.contains("amex")
            || name_lower.contains("american express")
            || name_lower.contains("discover")
            || name_lower.contains("jcb")
            || name_lower.contains("credit card")
            || name_lower.contains("credit-card")
        {
            return "cc";
        }
        if name_lower.contains("iban") {
            return "iban";
        }
        return "generic";
    }
    // secret subcategory from name
    if name_lower.contains("aws") || name_lower.contains("amazon") {
        return "aws";
    }
    if name_lower.contains("github") {
        return "github";
    }
    if name_lower.contains("gitlab") {
        return "gitlab";
    }
    if name_lower.contains("stripe") {
        return "stripe";
    }
    if name_lower.contains("slack") {
        return "slack";
    }
    if name_lower.contains("sendgrid") {
        return "sendgrid";
    }
    if name_lower.contains("npm") {
        return "npm";
    }
    if name_lower.contains("pypi") {
        return "pypi";
    }
    if name_lower.contains("telegram") {
        return "telegram";
    }
    "generic"
}

/// parse Nosey Parker YAML without serde_yml (avoids libyml overflow on long example strings)
/// NP files have the structure: rules: [list of rule objects with id, name, pattern, categories,
/// examples, negative_examples]. The pattern field uses YAML block scalars (|) or single-quoted
/// strings. Examples can contain very long base64 strings that crash libyml.
fn parse_np_file(content: &str, file_path: &str) -> Vec<NpRule> {
    let mut rules: Vec<NpRule> = Vec::new();

    // state machine over lines
    #[derive(PartialEq, Debug)]
    enum Field {
        None,
        Name,
        Id,
        Pattern,
        PatternBlock { indent: usize },
        Categories,
        Examples,
        NegativeExamples,
        Skip, // skip references and other fields we don't need
    }

    let mut state = Field::None;
    let mut current: Option<NpRule> = None;
    let mut block_indent: usize = 0;

    macro_rules! new_rule {
        () => {
            NpRule {
                id: String::new(),
                name: String::new(),
                pattern: String::new(),
                categories: vec![],
                examples: vec![],
                negative_examples: vec![],
            }
        };
    }

    // flush helper: push current rule if it has id and pattern
    fn flush(current: &mut Option<NpRule>, rules: &mut Vec<NpRule>) {
        if let Some(rule) = current.take() {
            if !rule.id.is_empty() && !rule.pattern.is_empty() {
                rules.push(rule);
            }
        }
    }

    for line in content.lines() {
        // detect start of a new rule: "- name:" at indent 0 (after stripping leading "  ")
        // NP files use "- name:" or "  - name:" as list item indicators
        let trimmed = line.trim_start();

        // detect new rule start: line starts with "- name:" (any leading whitespace)
        if trimmed.starts_with("- name:") || trimmed == "-" {
            flush(&mut current, &mut rules);
            current = Some(new_rule!());
            if trimmed.starts_with("- name:") {
                let val = trimmed["- name:".len()..].trim();
                if let Some(ref mut rule) = current {
                    rule.name = unquote_yaml_scalar(val).to_string();
                }
            }
            state = Field::None;
            continue;
        }

        // if no current rule yet, skip
        if current.is_none() {
            continue;
        }

        // handle block scalar continuation
        if let Field::PatternBlock { indent: expected } = state {
            let leading = line.len() - line.trim_start().len();
            // empty line inside block scalar — preserve as newline
            if line.trim().is_empty() {
                if let Some(ref mut rule) = current {
                    rule.pattern.push('\n');
                }
                continue;
            }
            // if indented enough, it's part of the block
            if leading >= expected {
                if let Some(ref mut rule) = current {
                    rule.pattern.push_str(&line[expected..]);
                    rule.pattern.push('\n');
                }
                continue;
            } else {
                // end of block scalar
                state = Field::None;
                // fall through to process this line as a key
            }
        }

        // skip long example lines (>2000 chars) to avoid passing them to downstream
        // fixtures building is done carefully below with length check
        let is_list_item = trimmed.starts_with("- ") || trimmed.starts_with("- |");

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
                // block scalar: next indented lines are the pattern
                let base_indent = line.len() - line.trim_start().len();
                block_indent = base_indent + 2; // block scalar body is indented 2 more
                state = Field::PatternBlock {
                    indent: block_indent,
                };
                if let Some(ref mut rule) = current {
                    rule.pattern.clear();
                }
            } else {
                // inline pattern (single or double quoted or bare)
                if let Some(ref mut rule) = current {
                    rule.pattern = unquote_yaml_scalar(val).to_string();
                }
                state = Field::None;
            }
        } else if trimmed.starts_with("categories:") {
            state = Field::Categories;
        } else if trimmed.starts_with("examples:") {
            state = Field::Examples;
        } else if trimmed.starts_with("negative_examples:") {
            state = Field::NegativeExamples;
        } else if trimmed.starts_with("references:") {
            state = Field::Skip;
        } else if is_list_item {
            match state {
                Field::Categories => {
                    let val = trimmed["- ".len()..].trim();
                    if let Some(ref mut rule) = current {
                        rule.categories.push(unquote_yaml_scalar(val).to_string());
                    }
                }
                Field::Examples => {
                    // only collect short examples (skip giant base64 blobs)
                    let val = trimmed["- ".len()..].trim();
                    if val != "|" && val.len() <= 500 {
                        if let Some(ref mut rule) = current {
                            rule.examples.push(unquote_yaml_scalar(val).to_string());
                        }
                    }
                    // for "- |" (block literal example), skip the whole block
                }
                Field::NegativeExamples => {
                    let val = trimmed["- ".len()..].trim();
                    if val != "|" && val.len() <= 500 {
                        if let Some(ref mut rule) = current {
                            rule.negative_examples
                                .push(unquote_yaml_scalar(val).to_string());
                        }
                    }
                }
                _ => {}
            }
        } else if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("- ") {
            // unknown field key — could be an end of a list block; only reset state
            // if this line looks like a key: value
            if trimmed.contains(':') && !trimmed.starts_with(' ') {
                // top-level key — reset state (not a list continuation)
                match state {
                    Field::Categories | Field::Examples | Field::NegativeExamples | Field::Skip => {
                        state = Field::None;
                    }
                    _ => {}
                }
            }
        }
    }
    // flush final rule
    flush(&mut current, &mut rules);

    let _ = file_path; // suppress unused warning
    rules
}

/// parse secrets-patterns-db YAML without serde_yml (avoids libyml overflow on large files)
/// format is rigid: patterns: list of {pattern: {name, regex, confidence}}
fn parse_spdb_file(content: &str, file_path: &str) -> Vec<SpdbPattern> {
    let mut patterns: Vec<SpdbPattern> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_regex: Option<String> = None;
    let mut current_confidence: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("name:") {
            // flush previous pattern if complete
            if let (Some(name), Some(regex), Some(confidence)) = (
                current_name.take(),
                current_regex.take(),
                current_confidence.take(),
            ) {
                patterns.push(SpdbPattern {
                    name,
                    regex,
                    confidence,
                });
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
    // flush last pattern
    if let (Some(name), Some(regex), Some(confidence)) =
        (current_name, current_regex, current_confidence)
    {
        patterns.push(SpdbPattern {
            name,
            regex,
            confidence,
        });
    }

    if patterns.is_empty() {
        panic!(
            "rule_pipeline: parse_spdb_file: no patterns found in {} — file may be empty or malformed",
            file_path
        );
    }
    patterns
}

/// strip YAML quoting from a scalar value: "value" or 'value' → value
fn unquote_yaml_scalar(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// ── run ────────────────────────────────────────────────────────────────────────
/// Run the rule normalization pipeline.
///
/// Reads vendor sources, normalizes, dedups, validates, and writes
/// `rules/combined.yaml` + `rules/patterns-test-fixtures.yaml`.
///
/// Panics on any malformed input or invalid regex (zero-tolerance per D-04).
#[allow(clippy::too_many_lines)]
pub fn run(opts: &RunOptions) -> RunResult {
    let quiet = opts.quiet;

    // ── step 1: load exclusions ────────────────────────────────────────────────
    let exclusions_raw = fs::read_to_string("rules/EXCLUSIONS.yaml")
        .unwrap_or_else(|e| panic!("rule_pipeline: cannot read rules/EXCLUSIONS.yaml: {}", e));
    let exclusions: Exclusions = serde_yml::from_str(&exclusions_raw)
        .unwrap_or_else(|e| panic!("rule_pipeline: malformed rules/EXCLUSIONS.yaml: {}", e));
    let excluded_ids: HashSet<String> = exclusions.excluded.into_iter().collect();
    log_progress!(quiet, "rule_pipeline: loaded {} exclusions", excluded_ids.len());

    // ── step 2: parse gitleaks TOML ───────────────────────────────────────────
    let gl_raw = fs::read_to_string("rules/vendor/gitleaks/gitleaks.toml").unwrap_or_else(|e| {
        panic!(
            "rule_pipeline: cannot read rules/vendor/gitleaks/gitleaks.toml: {}",
            e
        )
    });
    let gl_file: GitleaksFile = toml::from_str(&gl_raw)
        .unwrap_or_else(|e| panic!("rule_pipeline: malformed gitleaks.toml: {}", e));

    let mut gl_rules: Vec<NormalizedRule> = Vec::new();
    for rule in gl_file.rules {
        if excluded_ids.contains(&rule.id) {
            continue;
        }
        // skip path-only rules (no regex field — file path matching not relevant for proxy)
        let regex = match rule.regex {
            Some(r) => r,
            None => {
                log_progress!(quiet,
                    "rule_pipeline: skipping gitleaks rule {} — no regex (path-only rule)",
                    rule.id
                );
                continue;
            }
        };
        let (category, subcategory) = gl_subcategory(&rule.id);
        let confidence = infer_confidence_gitleaks(&regex);
        let replacement_type = derive_replacement_type(category, subcategory);
        let severity = derive_severity(confidence);
        gl_rules.push(NormalizedRule {
            id: format!("gl.{}", rule.id),
            name: rule.description.clone().unwrap_or_else(|| rule.id.clone()),
            category: category.to_string(),
            subcategory: subcategory.to_string(),
            source: "gitleaks".to_string(),
            confidence: confidence.to_string(),
            regex,
            keywords: rule.keywords.unwrap_or_default(),
            entropy: rule.entropy,
            tags: rule.tags.unwrap_or_default(),
            checksum_type: None,
            replacement_type: replacement_type.to_string(),
            description: rule.description.unwrap_or_default(),
            severity: severity.to_string(),
        });
    }
    log_progress!(quiet,
        "rule_pipeline: gitleaks parsed {} included rules",
        gl_rules.len()
    );

    // ── step 3: parse secrets-patterns-db YAML ────────────────────────────────
    // uses hand-rolled line parser (serde_yml / libyml panics on large files with long scalars)
    let mut spdb_rules: Vec<NormalizedRule> = Vec::new();
    let mut spdb_slug_counts: HashMap<String, usize> = HashMap::new();

    // SPDB include policy (strict allow-list per CURATED-MANIFEST.md):
    // - rules-stable.yml (secrets): all SPDB secret patterns are DUPLICATE or LOW-CONFIDENCE;
    //   skip entirely — NP/gitleaks cover these with better precision
    // - pii-stable.yml (PII): only the 9 explicitly curated patterns; pii-stable has 144 patterns
    //   but most are out-of-scope (bank routing, crypto, SSL, etc.) or have incompatible regex
    let spdb_pii_allowlist: HashSet<&str> = [
        "ssn_number - 3",
        "emails",
        "phones_with_exts",
        "visa_credit_card",
        "american_express_credit-card",
        "MasterCard",
        "Discover",
        "JCB",
        "iban_numbers",
    ]
    .iter()
    .cloned()
    .collect();

    for (path, category) in &[("rules/vendor/secrets-patterns-db/pii-stable.yml", "pii")] {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("rule_pipeline: cannot read {}: {}", path, e));
        let patterns = parse_spdb_file(&raw, path);

        for p in patterns {
            // apply strict allow-list (only curated PII patterns pass)
            if !spdb_pii_allowlist.contains(p.name.as_str()) {
                continue;
            }
            // also apply exclusion list (ssn - 3, ssn_number, phones with lookaheads, etc.)
            if excluded_ids.contains(&p.name) {
                continue;
            }
            // slug collision handling
            let base_slug = slugify(&p.name);
            let count = spdb_slug_counts.entry(base_slug.clone()).or_insert(0);
            *count += 1;
            let id = if *count == 1 {
                format!("spdb.{}", base_slug)
            } else {
                format!("spdb.{}-{}", base_slug, count)
            };

            let subcategory = spdb_subcategory(&p.name, category);
            let confidence = p.confidence.as_str();
            let replacement_type = derive_replacement_type(category, subcategory);
            let severity = derive_severity(confidence);
            spdb_rules.push(NormalizedRule {
                id,
                name: p.name,
                category: category.to_string(),
                subcategory: subcategory.to_string(),
                source: "secrets-patterns-db".to_string(),
                confidence: confidence.to_string(),
                regex: p.regex,
                keywords: vec![],
                entropy: None,
                tags: vec![],
                checksum_type: if subcategory == "cc" {
                    Some("luhn".to_string())
                } else {
                    None
                },
                replacement_type: replacement_type.to_string(),
                description: String::new(),
                severity: severity.to_string(),
            });
        }
    }
    log_progress!(quiet,
        "rule_pipeline: secrets-patterns-db parsed {} included rules",
        spdb_rules.len()
    );

    // ── step 4: parse Nosey Parker YAML ───────────────────────────────────────
    // uses custom line-based parser (serde_yml / libyml panics on NP files with long example lines)
    let np_rules_dir = Path::new("rules/vendor/nosey-parker/rules");
    let mut np_rules: Vec<NormalizedRule> = Vec::new();
    let mut test_fixtures: Vec<TestFixture> = Vec::new();

    let mut np_entries: Vec<_> = fs::read_dir(np_rules_dir)
        .unwrap_or_else(|e| panic!("rule_pipeline: cannot read NP rules dir: {}", e))
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yml")
                .unwrap_or(false)
        })
        .collect();
    // sort for deterministic ordering
    np_entries.sort_by_key(|e| e.path());

    for entry in &np_entries {
        let path = entry.path();

        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("rule_pipeline: cannot read NP file {:?}: {}", path, e));
        let np_file_rules = parse_np_file(&raw, &path.to_string_lossy());

        for rule in np_file_rules {
            if excluded_ids.contains(&rule.id) {
                continue;
            }
            let (category, subcategory) = np_subcategory(&rule.id);
            let confidence = infer_confidence_np(&rule.categories);
            let replacement_type = derive_replacement_type(category, subcategory);
            let severity = derive_severity(confidence);

            // collect test fixtures (examples/negative_examples)
            if !rule.examples.is_empty() || !rule.negative_examples.is_empty() {
                test_fixtures.push(TestFixture {
                    id: rule.id.clone(),
                    examples: rule.examples.clone(),
                    negative_examples: rule.negative_examples.clone(),
                });
            }

            // NP categories → tags (NOT category)
            let tags = rule.categories.clone();

            np_rules.push(NormalizedRule {
                id: rule.id,
                name: rule.name,
                category: category.to_string(),
                subcategory: subcategory.to_string(),
                source: "nosey-parker".to_string(),
                confidence: confidence.to_string(),
                regex: rule.pattern,
                keywords: vec![],
                entropy: None,
                tags,
                checksum_type: None,
                replacement_type: replacement_type.to_string(),
                description: String::new(),
                severity: severity.to_string(),
            });
        }
    }
    log_progress!(quiet,
        "rule_pipeline: nosey-parker parsed {} included rules",
        np_rules.len()
    );

    // write test fixtures file (overwrite each build for consistency)
    let fixtures_file = TestFixturesFile {
        fixtures: test_fixtures,
    };
    let fixtures_yaml = serde_yml::to_string(&fixtures_file)
        .unwrap_or_else(|e| panic!("rule_pipeline: failed to serialize test fixtures: {}", e));
    fs::write("rules/patterns-test-fixtures.yaml", fixtures_yaml).unwrap_or_else(|e| {
        panic!(
            "rule_pipeline: failed to write rules/patterns-test-fixtures.yaml: {}",
            e
        )
    });

    // ── step 5: parse hand-authored patterns ──────────────────────────────────
    let ha_raw =
        fs::read_to_string("rules/vendor/hand-authored/patterns.yaml").unwrap_or_else(|e| {
            panic!(
                "rule_pipeline: cannot read rules/vendor/hand-authored/patterns.yaml: {}",
                e
            )
        });
    let ha_file: HandAuthoredFile = serde_yml::from_str(&ha_raw).unwrap_or_else(|e| {
        panic!(
            "rule_pipeline: malformed rules/vendor/hand-authored/patterns.yaml: {}",
            e
        )
    });
    let mut ha_rules: Vec<NormalizedRule> = ha_file.rules;

    // ensure all ha.* ids are prefixed
    for rule in &mut ha_rules {
        if !rule.id.starts_with("ha.") {
            rule.id = format!("ha.{}", rule.id);
        }
    }

    // validate required hand-authored ids are present
    let required_ha = [
        "ha.pii.uk-nin",
        "ha.pii.pl-pesel",
        "ha.pii.fr-insee",
        "ha.pii.de-taxid",
        "ha.secret.ibm-cloud-iam",
    ];
    for req in &required_ha {
        if !ha_rules.iter().any(|r| r.id == *req) {
            panic!("rule_pipeline: required hand-authored rule {} is missing", req);
        }
    }
    log_progress!(quiet, "rule_pipeline: hand-authored parsed {} rules", ha_rules.len());

    // ── step 6: merge and deduplicate ─────────────────────────────────────────
    // insert in reverse priority order: spdb first (lowest), then gl, then np, then ha (highest)
    let mut merged: HashMap<String, NormalizedRule> = HashMap::new();
    for rule in spdb_rules
        .iter()
        .chain(gl_rules.iter())
        .chain(np_rules.iter())
        .chain(ha_rules.iter())
    {
        merged.insert(rule.id.clone(), rule.clone());
    }
    let mut final_rules: Vec<NormalizedRule> = merged.into_values().collect();
    final_rules.sort_by(|a, b| a.id.cmp(&b.id));
    log_progress!(quiet, "rule_pipeline: {} rules after merge+dedup", final_rules.len());

    if final_rules.is_empty() {
        panic!("rule_pipeline: no rules after normalization — normalization pipeline failed");
    }

    // ── step 7: validate each rule ────────────────────────────────────────────
    let valid_replacement_types = [
        "faker_email",
        "faker_phone",
        "faker_ssn",
        "faker_cc_luhn",
        "faker_iban",
        "faker_uuid",
        "faker_ipv4",
        "faker_aws_key",
        "faker_github_pat",
        "faker_jwt",
        "faker_api_key",
        "faker_db_conn",
        "faker_url_cred",
        "fpe_numeric",
        "generic_random",
        "passthrough",
    ];
    let valid_categories = ["secret", "pii", "infra"];

    // sequential cheap checks: id format, duplicate detection, category/replacement_type
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for rule in &final_rules {
        assert!(
            !rule.id.is_empty() && !rule.id.contains(char::is_whitespace),
            "rule_pipeline: rule has invalid id (empty or contains whitespace): {:?}",
            rule.id
        );
        assert!(
            seen_ids.insert(rule.id.as_str()),
            "rule_pipeline: duplicate id after dedup: {}",
            rule.id
        );
        assert!(
            valid_categories.contains(&rule.category.as_str()),
            "rule_pipeline: rule {} has invalid category '{}' (must be secret|pii|infra)",
            rule.id,
            rule.category
        );
        assert!(
            valid_replacement_types.contains(&rule.replacement_type.as_str()),
            "rule_pipeline: rule {} has invalid replacement_type '{}'. Valid values: {:?}",
            rule.id,
            rule.replacement_type,
            valid_replacement_types
        );
        if (rule.category == "secret" || rule.category == "pii") && rule.keywords.is_empty() {
            log_progress!(quiet,
                "rule_pipeline: warn: rule {} ({}) has no keywords — regex runs on every body that passes combined pre-filter",
                rule.id, rule.category
            );
        }
    }

    // parallel regex compilation — the expensive part (NFA + lazy DFA scaffolding per rule)
    use rayon::prelude::*;
    final_rules.par_iter().for_each(|rule| {
        let cleaned_regex = strip_posix_comments(&rule.regex);
        regex::bytes::RegexBuilder::new(&cleaned_regex)
            .size_limit(256 * 1024 * 1024)
            .dfa_size_limit(256 * 1024 * 1024)
            .build()
            .unwrap_or_else(|e| panic!("rule_pipeline: invalid regex in rule {}: {}", rule.id, e));
    });
    log_progress!(quiet, "rule_pipeline: validated {} rules", final_rules.len());

    // ── step 8: write combined.yaml ───────────────────────────────────────────
    let attribution = "# This file is generated by `cargo run --bin build-rules`. DO NOT EDIT MANUALLY.\n\
        # See rules/vendor/ for upstream sources.\n\
        #\n\
        # Attribution:\n\
        # - secrets-patterns-db (CC-BY 4.0): https://github.com/mazen160/secrets-patterns-db\n\
        #   License: Creative Commons Attribution 4.0 (CC-BY 4.0)\n\
        #   Attribution: Mazin Ahmed / secrets-patterns-db contributors\n\
        #   See: rules/vendor/secrets-patterns-db/LICENSE\n";

    if let Some(n) = opts.max_rules {
        log_progress!(quiet, "rule_pipeline: applying max_rules limit of {} rules (round-robin across vendors)", n);
        // bucket by source, preserving alphabetical order within each bucket
        let mut buckets: HashMap<String, Vec<NormalizedRule>> = HashMap::new();
        for rule in final_rules.drain(..) {
            buckets.entry(rule.source.clone()).or_default().push(rule);
        }
        // stable vendor order so output is deterministic
        let mut sources: Vec<String> = buckets.keys().cloned().collect();
        sources.sort();
        let mut iters: Vec<_> = sources.iter().map(|s| buckets.remove(s).unwrap().into_iter()).collect();
        let mut picked: Vec<NormalizedRule> = Vec::with_capacity(n);
        'outer: loop {
            let mut progressed = false;
            for it in iters.iter_mut() {
                if let Some(rule) = it.next() {
                    picked.push(rule);
                    progressed = true;
                    if picked.len() >= n {
                        break 'outer;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        picked.sort_by(|a, b| a.id.cmp(&b.id));
        final_rules = picked;
    }

    let combined = CombinedFile {
        rules: &final_rules,
    };
    let yaml = serde_yml::to_string(&combined)
        .unwrap_or_else(|e| panic!("rule_pipeline: failed to serialize combined.yaml: {}", e));
    let combined_path = "rules/combined.yaml";
    fs::write(combined_path, format!("{}{}", attribution, yaml))
        .unwrap_or_else(|e| panic!("rule_pipeline: failed to write rules/combined.yaml: {}", e));

    log_progress!(quiet,
        "rule_pipeline: wrote {} with {} rules",
        combined_path,
        final_rules.len()
    );

    RunResult {
        gitleaks_rules: gl_rules.len(),
        spdb_rules: spdb_rules.len(),
        np_rules: np_rules.len(),
        ha_rules: ha_rules.len(),
        total_rules: final_rules.len(),
        combined_path: combined_path.to_string(),
        fixtures_path: "rules/patterns-test-fixtures.yaml".to_string(),
    }
}

// NOTE: build.rs tests are in tests/build_pipeline.rs
// build.rs is a separate compilation unit — #[cfg(test)] here is not run by `cargo test`
// the test file reimplements helpers inline to avoid the import limitation

#[cfg(test)]
mod tests {
    use super::*;

    // ── helper tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("AWS API Key"), "aws-api-key");
        // dots become hyphens (non-alphanumeric collapses)
        assert_eq!(slugify("U.S. Phone Number"), "u-s-phone-number");
        assert_eq!(slugify("Stripe API Key"), "stripe-api-key");
        assert_eq!(slugify("ssn_number - 3"), "ssn-number-3");
    }

    #[test]
    fn test_gitleaks_confidence() {
        // contains literal "sk_test_" or "sk_live_" inline → high
        let inline_literal = r"\b(sk_test_[a-zA-Z0-9]{20,99})\b";
        assert_eq!(infer_confidence_gitleaks(inline_literal), "high");

        // alternation form like (?:sk|rk)_(?:test|live)_ doesn't contain the
        // literal "sk_test" substring, so it falls through to medium
        let alternation = r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b";
        assert_eq!(infer_confidence_gitleaks(alternation), "medium");

        // context-anchored: contains "=" operator
        let context = r"(?i)(?:adafruit)[^0-9a-z\-_](?:[0-9a-z\-_]{0,50}?)([0-9a-z]{32})";
        assert_eq!(infer_confidence_gitleaks(context), "medium");

        // akia prefix → high
        let aws = r"\b(AKIA[A-Z0-9]{16})\b";
        assert_eq!(infer_confidence_gitleaks(aws), "high");
    }

    #[test]
    fn test_np_confidence() {
        // categories without "fuzzy" → high
        let high_cats = vec!["api".to_string(), "identifier".to_string()];
        assert_eq!(infer_confidence_np(&high_cats), "high");

        // categories with "fuzzy" → medium
        let fuzzy_cats = vec!["api".to_string(), "fuzzy".to_string(), "secret".to_string()];
        assert_eq!(infer_confidence_np(&fuzzy_cats), "medium");

        // empty categories → high (no fuzzy marker)
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
        // same id from all 4 sources — hand-authored must win
        let spdb_rule = NormalizedRule {
            id: "test.duplicate".to_string(),
            name: "From SPDB".to_string(),
            category: "pii".to_string(),
            subcategory: "email".to_string(),
            source: "secrets-patterns-db".to_string(),
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
        let gl_rule = NormalizedRule {
            id: "test.duplicate".to_string(),
            name: "From Gitleaks".to_string(),
            source: "gitleaks".to_string(),
            ..spdb_rule.clone()
        };
        let np_rule = NormalizedRule {
            id: "test.duplicate".to_string(),
            name: "From NP".to_string(),
            source: "nosey-parker".to_string(),
            ..spdb_rule.clone()
        };
        let ha_rule = NormalizedRule {
            id: "test.duplicate".to_string(),
            name: "From Hand-Authored".to_string(),
            source: "hand-authored".to_string(),
            ..spdb_rule.clone()
        };

        // build dedup map: spdb first, then gl, then np, then ha (highest priority overwrites)
        let mut dedup: HashMap<String, NormalizedRule> = HashMap::new();
        dedup.insert(spdb_rule.id.clone(), spdb_rule);
        dedup.insert(gl_rule.id.clone(), gl_rule);
        dedup.insert(np_rule.id.clone(), np_rule);
        dedup.insert(ha_rule.id.clone(), ha_rule);

        let winner = dedup.get("test.duplicate").unwrap();
        // last insert wins in HashMap — ha is last, so hand-authored wins
        assert_eq!(
            winner.source, "hand-authored",
            "hand-authored should win dedup for duplicate ids"
        );
    }

    #[test]
    fn test_gitleaks_parser() {
        let fixture = include_str!("../tests/fixtures/gitleaks_snippet.toml");
        let gl_file: GitleaksFile =
            toml::from_str(fixture).expect("fixture must parse as gitleaks TOML");

        assert_eq!(gl_file.rules.len(), 2);

        let stripe = &gl_file.rules[0];
        assert_eq!(stripe.id, "stripe-access-token");
        assert!(stripe.regex.is_some(), "stripe rule must have regex");
        let regex = stripe.regex.as_ref().unwrap();
        // alternation form (sk|rk)_(test|live) doesn't contain the literal
        // substring "sk_test" so confidence falls through to medium
        assert_eq!(infer_confidence_gitleaks(regex), "medium");
        // id gets gl. prefix
        let normalized_id = format!("gl.{}", stripe.id);
        assert!(
            normalized_id.starts_with("gl."),
            "id must be prefixed with gl."
        );
        assert_eq!(stripe.tags.as_ref().unwrap(), &["stripe"]);
        assert_eq!(stripe.entropy.unwrap(), 2.0);
        assert_eq!(stripe.keywords.as_ref().unwrap(), &["sk_test", "sk_live"]);

        let adafruit = &gl_file.rules[1];
        assert_eq!(adafruit.id, "adafruit-api-key");
        let ada_regex = adafruit.regex.as_ref().unwrap();
        // context-anchored (contains (?i)) → medium confidence
        assert_eq!(infer_confidence_gitleaks(ada_regex), "medium");
        assert_eq!(format!("gl.{}", adafruit.id), "gl.adafruit-api-key");
    }

    #[test]
    fn test_spdb_parser() {
        let fixture = include_str!("../tests/fixtures/spdb_snippet.yaml");
        let patterns = parse_spdb_file(fixture, "tests/fixtures/spdb_snippet.yaml");

        assert_eq!(patterns.len(), 2);

        let aws = &patterns[0];
        assert_eq!(aws.name, "AWS API Key");
        assert_eq!(aws.confidence, "high");
        // id is slugified name with spdb. prefix
        let id = format!("spdb.{}", slugify(&aws.name));
        assert_eq!(id, "spdb.aws-api-key");
        // source is "secrets-patterns-db"
        // (the parser returns raw SpdbPattern; source assignment happens in main pipeline)

        let stripe = &patterns[1];
        assert_eq!(stripe.name, "Stripe API Key");
        assert_eq!(stripe.confidence, "high");
        assert_eq!(
            format!("spdb.{}", slugify(&stripe.name)),
            "spdb.stripe-api-key"
        );
    }

    #[test]
    fn test_np_parser() {
        let fixture = include_str!("../tests/fixtures/np_snippet.yaml");
        let rules = parse_np_file(fixture, "tests/fixtures/np_snippet.yaml");

        assert_eq!(rules.len(), 2, "expected 2 rules from np fixture");

        let aws1 = &rules[0];
        assert_eq!(
            aws1.id, "np.aws.1",
            "NP id must be verbatim (already namespaced)"
        );
        assert_eq!(aws1.name, "AWS API Key");
        assert!(
            aws1.categories.contains(&"api".to_string()),
            "categories must include 'api'"
        );
        // no fuzzy → high confidence
        assert_eq!(infer_confidence_np(&aws1.categories), "high");
        // categories mapped to tags, NOT category field
        assert!(
            !aws1.categories.is_empty(),
            "categories must be preserved for tag mapping"
        );
        assert!(!aws1.pattern.is_empty(), "pattern must be present");

        let aws2 = &rules[1];
        assert_eq!(aws2.id, "np.aws.2");
        assert!(
            aws2.categories.contains(&"fuzzy".to_string()),
            "aws2 must have fuzzy category"
        );
        assert_eq!(infer_confidence_np(&aws2.categories), "medium");
        // multiline (?x) pattern must be preserved with newlines
        assert!(
            aws2.pattern.contains('\n'),
            "multiline pattern must preserve newlines"
        );
        assert!(aws2.pattern.contains("(?x)"), "(?x) flag must be preserved");
    }

    #[test]
    fn test_invalid_regex_fails_validation() {
        // a regex with an unclosed group should fail to compile
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
}
