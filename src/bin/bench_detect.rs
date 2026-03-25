// benchmark: detection algorithms across input sizes
// algorithms: aho-corasick, regex, shannon entropy
// measures: avg wall-clock time per iteration, throughput in MB/s

// pattern set: 82 included patterns from docs/analysis/CURATED-MANIFEST.md
// sources: gitleaks, nosey-parker, secrets-patterns-db, detect-secrets
// generated: 2026-03-25
const CURATED_PATTERN_COUNT: usize = 82; // update if patterns are added/skipped

use aho_corasick::AhoCorasick;
use regex::Regex;
use std::time::Instant;

// --- input generation ---

const ENGLISH_PARAGRAPH: &str = "The quick brown fox jumps over the lazy dog near the river bank. \
    Scientists have discovered a new species of butterfly in the Amazon rainforest. \
    The stock market experienced significant volatility during the trading session. \
    Engineers are working on new solutions to reduce carbon emissions globally. \
    The conference proceedings will be published in the international journal. \
    Authentication systems must balance security and usability for end users. \
    Network packets are routed through multiple hops before reaching their destination. \
    Machine learning models require large datasets to achieve high accuracy. \
    The deployment pipeline automates testing, building, and releasing software. \
    Configuration management ensures consistent environments across all servers. ";

const CODE_SNIPPET: &str = r#"
fn process_request(req: &Request) -> Result<Response, Error> {
    let token = req.headers().get("Authorization");
    let user_id = extract_user_id(&token)?;
    let db = Database::connect("postgresql://localhost:5432/app")?;
    let result = db.query("SELECT * FROM users WHERE id = $1", &[&user_id])?;
    Ok(Response::new(StatusCode::OK, result))
}

const API_BASE: &str = "https://api.example.com/v1";
const TIMEOUT_MS: u64 = 5000;

pub struct Config {
    pub host: String,
    pub port: u16,
    pub debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { host: "localhost".into(), port: 8080, debug: false }
    }
}
"#;

const SECRET_SNIPPET: &str = concat!(
    "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n",
    "contact: user@example.com phone: 415-555-0132 ssn: 123-45-6789\n",
    "card: 4532015112830366 exp: 12/26\n",
    "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sig\n",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAcMsbkDt4Xl\n-----END RSA PRIVATE KEY-----\n",
    "password=S3cr3tP@ssw0rd123\n",
    "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
    "DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod\n",
);

// --- fp corpus: clean llm prompt/response samples (no real credentials) ---
// each entry is a realistic llm conversation fragment; none contain real secrets
const FP_CORPUS: &[&str] = &[
    // 1. security tutorial text
    "To configure AWS, set AWS_ACCESS_KEY_ID to your key. Example: AKIAIOSFODNN7EXAMPLE is shown in docs.",
    // 2. GitHub docs example
    "Personal access tokens start with ghp_ followed by 36 characters. Example: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    // 3. email in prose
    "Send the report to john.smith@acme-corp.com or the team list team@example.org for review.",
    // 4. phone in prose
    "Call us at (415) 555-0100 or toll-free 1-800-555-0199 for support.",
    // 5. SSN discussion
    "The SSN format is XXX-XX-XXXX where each X is a digit, e.g. 123-45-6789 as a placeholder.",
    // 6. credit card education
    "Visa cards start with 4, e.g. 4111111111111111 is the standard test number. Never use real card numbers.",
    // 7. IPv4 in docs
    "Default gateway is typically 192.168.1.1, and DNS servers are often 8.8.8.8 and 8.8.4.4",
    // 8. UUID in logs
    "Transaction ID: 550e8400-e29b-41d4-a716-446655440000 was processed successfully.",
    // 9. JWT example
    "A JWT looks like eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.XXXXXXXXXX",
    // 10. connection string docs
    "The format is postgresql://user:password@host:5432/dbname — replace password with your actual password.",
    // 11. PEM block discussion
    "-----BEGIN RSA PRIVATE KEY----- marks the start of a PEM-encoded private key. Never commit this to git.",
    // 12. password policy text
    "Passwords must be at least 12 characters. Avoid using password=12345 or similar weak values.",
    // 13. OpenAI docs
    "API keys look like sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX. Store them in environment variables.",
    // 14. Bearer token docs
    "Authorization: Bearer <your-token-here> — replace with the token from the dashboard.",
    // 15. Database URL config example
    "DATABASE_URL=postgresql://localhost:5432/mydb_development (no password for local dev)",
    // 16. code review comment
    "I see you hardcoded API_KEY=abc123def456 — please move this to an environment variable.",
    // 17. regex discussion
    r"The email regex [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} matches most common email formats.",
    // 18. security audit finding
    "Found potential leak: line 42 contains what looks like an AWS key AKIAXXXXXXXXXXXXXXXX but may be a test value.",
    // 19. generic prose with no secrets
    "The deployment pipeline runs tests on every commit. If tests pass, the artifact is promoted to staging.",
    // 20. code snippet with placeholder values
    "const token = process.env.GITHUB_TOKEN; // set this in your .env file, e.g. ghp_yourtoken",
];

fn generate_input(target_bytes: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_bytes + 2048);

    // build a base chunk: ~80% prose + code, ~20% secret material
    let prose_block = format!("{}{}", ENGLISH_PARAGRAPH, CODE_SNIPPET);
    let secret_block = SECRET_SNIPPET;

    while buf.len() < target_bytes {
        let remaining = target_bytes.saturating_sub(buf.len());
        if remaining > prose_block.len() {
            buf.push_str(&prose_block);
        } else {
            buf.push_str(&prose_block[..remaining.min(prose_block.len())]);
        }

        // embed a secret chunk roughly every 2 KB of prose
        if buf.len() % 2048 < prose_block.len().min(2048) {
            buf.push_str(secret_block);
        }
    }

    buf.truncate(target_bytes);
    buf.into_bytes()
}

// --- aho-corasick algorithm ---

fn build_aho_corasick() -> AhoCorasick {
    let patterns: &[&str] = &[
        // --- secret/aws prefixes ---
        "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T",
        "ABSK",
        "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY",
        "aws_access_key_id", "AWS_ACCESS_KEY_ID",
        "bedrock-api-key",
        // --- secret/anthropic ---
        "sk-ant-api", "sk-ant-admin",
        // --- secret/openai ---
        "sk-proj-", "sk-svcacct-", "sk-admin-", "T3BlbkFJ",
        // --- secret/github ---
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        // --- secret/gitlab ---
        "glpat-", "glptt-", "GR1348941", "glcbt-", "gldt-", "glft-", "glimt-",
        "glagent-", "gloas-", "glrt-", "glsoat-", "_gitlab_session=",
        // --- secret/stripe ---
        "sk_test_", "sk_live_", "sk_prod_", "rk_test_", "rk_live_", "rk_prod_",
        // --- secret/slack ---
        "xoxb-", "xoxp-", "xoxe.", "xoxa-", "xoxr-", "xapp-",
        "hooks.slack.com/services/",
        // --- secret/jwt ---
        "eyJ",
        // --- secret/private-key ---
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        // --- secret/db-conn ---
        "postgresql://", "postgres://", "mongodb://", "mongodb+srv://",
        // --- secret/sendgrid ---
        "SG.",
        // --- secret/npm ---
        "npm_",
        // --- secret/pypi ---
        "pypi-AgEIcHlwaS5vcmc", "pypi-AgENdGVzdC5weXBpLm9yZw",
        // --- secret/various prefix-anchored ---
        "dapi", "dop_v1_", "dp.pt.",
        "AIza", "hf_", "api_org_",
        "glc_", "glsa_",
        "hvs.", "hvb.",
        "lin_api_",
        "NRJS-", "NRAK-",
        "pplx-", "pscale_tkn_", "pscale_oauth_", "pscale_pw_",
        "PMAK-", "pnu_",
        "rdme_", "rubygems_",
        "sgp_",
        "shpat_", "shpca_", "shppa_", "shpss_",
        "shippo_live_", "shippo_test_",
        "sm_aat_", "sm_pat_", "sm_sat_",
        "squ_",
        "tk-us-",
        "xkeysib-",
        "sntryu_",
        "EAAA", "sq0atp-",
        "EZAK", "EZTK",
        "duffel_",
        "fio-u-",
        "fo1_", "fm1",
        "LTAI",
        "v1.0-",
        "ico-",
        "pul-",
        "CLOJARS_",
        "4b1d",
        "dt0c01.", "dt0s01.",
        "dnkey-",
        "HRKU-",
        "API-",
        "FLWSECK_TEST-", "FLWPUBK_TEST-", "FLWSECK-",
        "AGE-SECRET-KEY-1",
        "ops_eyJ",
        "typeform", "tfp_",
        // --- pii context words ---
        "password=", "PASSWORD=", "passwd=",
        "DATABASE_URL", "DB_PASSWORD",
        // --- detect-secrets specific ---
        "AccountKey=",
        "api.softlayer.com",
        "ibm_cos",
    ];
    AhoCorasick::new(patterns).expect("failed to build aho-corasick automaton")
}

fn run_aho_corasick(ac: &AhoCorasick, input: &[u8]) -> usize {
    ac.find_iter(input).count()
}

// --- regex algorithm ---

fn build_regexes() -> Vec<Regex> {
    let patterns: &[(&str, &str)] = &[
        // --- secret/aws ---
        ("np.aws.1", r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
        // np.aws.2: context-anchored AWS secret key (verbose pattern flattened)
        ("np.aws.2", r"(?i)\baws_?(?:secret)?_?(?:access)?_?key['`]?\s{0,30}(?::|=>|=)\s{0,30}['`]?([a-z0-9/+=]{40})"),
        ("aws-bedrock-long", r"\b(ABSK[A-Za-z0-9+/]{109,269}=*)"),
        // bedrock short-lived: literal prefix detection only (not a secret value pattern, kept for completeness)
        // SKIPPED: aws-amazon-bedrock-api-key-short-lived — literal string match only, no sensitive value to extract

        // --- secret/anthropic ---
        ("np.anthropic.1", r"\b(sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{95})"),
        ("anthropic-admin", r"\b(sk-ant-admin01-[a-zA-Z0-9_-]{93}AA)"),

        // --- secret/openai ---
        ("openai-api-key", r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"),

        // --- secret/github ---
        ("np.github.1", r"\b(ghp_[a-zA-Z0-9]{36})\b"),
        ("np.github.2", r"\b(gho_[a-zA-Z0-9]{36})\b"),
        ("np.github.3", r"\b((?:ghu|ghs)_[a-zA-Z0-9]{36})\b"),
        ("np.github.4", r"\b(ghr_[a-zA-Z0-9]{76})\b"),
        ("github-fine-grained-pat", r"github_pat_\w{82}"),

        // --- secret/gitlab ---
        ("np.gitlab.1", r"\b(glpat-[a-zA-Z0-9_-]{20})\b"),
        ("gitlab-ptt", r"glptt-[0-9a-f]{40}"),
        ("gitlab-rrt", r"GR1348941[\w-]{20}"),
        ("gitlab-pat-routable", r"\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{9}\b"),
        ("gitlab-cicd-job-token", r"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}"),
        ("gitlab-deploy-token", r"gldt-[0-9a-zA-Z_-]{20}"),
        ("gitlab-feed-token", r"glft-[0-9a-zA-Z_-]{20}"),
        ("gitlab-incoming-mail-token", r"glimt-[0-9a-zA-Z_-]{25}"),
        ("gitlab-kubernetes-agent-token", r"glagent-[0-9a-zA-Z_-]{50}"),
        ("gitlab-oauth-app-secret", r"gloas-[0-9a-zA-Z_-]{64}"),
        ("gitlab-runner-auth-token", r"glrt-[0-9a-zA-Z_-]{20}"),
        ("gitlab-scim-token", r"glsoat-[0-9a-zA-Z_-]{20}"),
        ("gitlab-session-cookie", r"_gitlab_session=[0-9a-z]{32}"),

        // --- secret/stripe ---
        ("stripe-access-token", r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})"),

        // --- secret/slack ---
        ("np.slack.2", r"\b(xoxb-[0-9]{10,12}-[0-9]{10,14}-[a-zA-Z0-9]{23,25})\b"),
        ("slack-app-token", r"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+"),
        ("slack-config-access-token", r"(?i)xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}"),
        ("slack-config-refresh-token", r"(?i)xoxe-\d-[A-Z0-9]{146}"),
        ("slack-legacy-bot-token", r"xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}"),
        ("slack-legacy-token", r"xox[os]-\d+-\d+-\d+-[a-fA-F0-9]+"),
        ("slack-legacy-workspace-token", r"xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}"),
        ("slack-user-token", r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"),
        ("slack-webhook-url", r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"),

        // --- secret/jwt ---
        ("np.jwt.1", r"\b(ey[a-zA-Z0-9_-]{12,}\.ey[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,})"),
        // jwt-base64: SKIPPED — named captures not supported in Rust regex crate as used in gitleaks pattern

        // --- secret/private-key ---
        ("private-key", r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
        // pkcs12-file: SKIPPED — binary file header pattern; not text-based

        // --- secret/db-conn ---
        ("np.postgres.1", r"(?:postgres|postgresql)://([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,}):([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,})@([a-zA-Z0-9_.-]{3,}(?::\d{1,5})?)"),
        ("np.mongo.1", r"(?:mongodb\+srv|mongodb)://([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,}):([a-zA-Z0-9%;._~!$&'()*+,;=-]{3,})@([a-zA-Z0-9_.-]{3,}(?::\d{1,5})?)"),
        // np.odbc.1: ODBC connection string password
        ("np.odbc.1", r"(?i)Password\s*=\s*([^;]{8,80})"),

        // --- secret/url-cred ---
        ("np.http.1-url-cred", r#"[a-zA-Z][a-zA-Z0-9+\-.]{1,30}://[^@\s"']{3,}:[^@\s"']{3,}@"#),

        // --- secret/sendgrid ---
        ("sendgrid-api-token", r"\b(SG\.(?i)[a-z0-9=_\-.]{66})"),

        // --- secret/mailchimp ---
        ("mailchimp-api-key", r"[0-9a-z]{32}-us[0-9]{1,2}"),

        // --- secret/npm ---
        ("npm-access-token", r"(?i)\b(npm_[a-z0-9]{36})"),
        // npm .npmrc format
        ("npm-npmrc-token", r"//.+/:_authToken=\s*(?:npm_[^\s]+|[A-Fa-f0-9-]{36})"),

        // --- secret/pypi ---
        // simplified: cap repetition to avoid DFA size limit (original {50,1000} exceeds 10MB)
        ("pypi-upload-token", r"pypi-AgEIcHlwaS5vcmc[\w\-]{50,200}"),
        ("pypi-test-token", r"pypi-AgENdGVzdC5weXBpLm9yZw[\w\-]{50,200}"),

        // --- secret/telegram ---
        ("telegram-bot-api-token", r"\b(\d{8,10}:[0-9A-Za-z_-]{35})\b"),

        // --- secret/twilio ---
        ("twilio-api-key", r"SK[0-9a-fA-F]{32}"),

        // --- secret/discord ---
        ("discord-api-token", r#"(?i)(?:discord)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>)[\s'"=]{0,5}([a-f0-9]{64})"#),
        ("discord-client-id", r#"(?i)(?:discord)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>)[\s'"=]{0,5}([0-9]{18})"#),
        ("discord-client-secret", r#"(?i)(?:discord)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>)[\s'"=]{0,5}([a-z0-9=_-]{32})"#),

        // --- secret/artifactory ---
        ("artifactory-api-key", r"\bAKCp[A-Za-z0-9]{69}\b"),
        ("artifactory-reference-token", r"\bcmVmd[A-Za-z0-9]{59}\b"),

        // --- secret/azure ---
        ("azure-ad-client-secret", r#"(?:^|['"` >=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})"#),
        ("azure-storage-key", r"AccountKey=[a-zA-Z0-9+/=]{88}"),

        // --- secret/cloudant ---
        ("cloudant-url", r"(?i)https?://[\w-]+:(?:[0-9a-f]{64}|[a-z]{24})@[\w-]+\.cloudant\.com"),

        // --- secret/ibm ---
        ("ibm-cos-hmac", r"(?i)(?:ibm)?[-_]?cos[-_]?(?:[\w-]{0,20})secret[-_]?access[-_]?key\s*[=:]\s*([a-f0-9]{48})"),

        // --- secret/square ---
        ("square-access-token", r"\b((?:EAAA|sq0atp-)[\w-]{22,60})"),
        ("squarespace-access-token", r#"(?i)(?:squarespace)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"#),

        // --- secret/softlayer ---
        ("softlayer-url", r"(?i)https?://api\.softlayer\.com/soap/v3(?:\.1)?/([a-z0-9]{64})"),

        // --- various saas prefix-anchored (high confidence) ---
        ("1password-secret-key", r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"),
        ("1password-service-account-token", r"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}"),
        ("age-secret-key", r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
        ("airtable-pat", r"\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b"),
        ("alibaba-access-key-id", r"\b(LTAI(?i)[a-z0-9]{20})"),
        ("atlassian-api-token", r"\b(ATATT3[A-Za-z0-9_=\-]{186})"),
        ("authress-service-client-access-key", r"\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})"),
        ("clickhouse-cloud-api-secret-key", r"\b(4b1d[A-Za-z0-9]{38})\b"),
        ("clojars-api-token", r"(?i)CLOJARS_[a-z0-9]{60}"),
        ("cloudflare-origin-ca-key", r"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})"),
        ("databricks-api-token", r"\b(dapi[a-f0-9]{32}(?:-\d)?)"),
        ("defined-networking-api-token", r#"(?i)(?:dnkey)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(dnkey-[a-z0-9=_-]{26}-[a-z0-9=_-]{52})"#),
        ("digitalocean-access-token", r"\b(doo_v1_[a-f0-9]{64})"),
        ("digitalocean-pat", r"\b(dop_v1_[a-f0-9]{64})"),
        ("digitalocean-refresh-token", r"(?i)\b(dor_v1_[a-f0-9]{64})"),
        ("doppler-api-token", r"dp\.pt\.(?i)[a-z0-9]{43}"),
        ("duffel-api-token", r"duffel_(?:test|live)_(?i)[a-z0-9_=\-]{43}"),
        ("dynatrace-api-token", r"dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}"),
        ("easypost-api-token", r"\bEZAK(?i)[a-z0-9]{54}\b"),
        ("easypost-test-api-token", r"\bEZTK(?i)[a-z0-9]{54}\b"),
        ("facebook-page-access-token", r"\b(EAA[MC](?i)[a-z0-9]{100,})"),
        ("flyio-access-token", r"\b(fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+/]{100,}={0,3}|fm2_[a-zA-Z0-9+/]{100,}={0,3})"),
        ("frameio-api-token", r"fio-u-(?i)[a-z0-9-_=]{64}"),
        ("gcp-api-key", r"\b(AIza[\w-]{35})"),
        ("grafana-cloud-api-token", r"(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})"),
        ("grafana-service-account-token", r"(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})"),
        ("harness-api-key", r"(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}"),
        ("heroku-api-key-v2", r"\b(HRKU-AA[0-9a-zA-Z_-]{58})"),
        ("huggingface-access-token", r"\b(hf_(?i:[a-z]{34}))"),
        ("huggingface-organization-api-token", r"\b(api_org_(?i:[a-z]{34}))"),
        ("infracost-api-token", r"\b(ico-[a-zA-Z0-9]{32})"),
        ("intra42-client-secret", r"\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})"),
        ("linear-api-key", r"lin_api_(?i)[a-z0-9]{40}"),
        ("maxmind-license-key", r"\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)"),
        ("microsoft-teams-webhook", r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}"),
        ("new-relic-browser-api-token", r#"(?i)(?:new-relic|newrelic|new_relic)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(NRJS-[a-f0-9]{19})"#),
        ("new-relic-user-api-key", r#"(?i)(?:new-relic|newrelic|new_relic)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(NRAK-[a-z0-9]{27})"#),
        ("notion-api-token", r"\b(ntn_[0-9]{11}[A-Za-z0-9]{35})"),
        ("npm-access-token-prefixed", r"(?i)\b(npm_[a-z0-9]{36})"),
        ("octopus-deploy-api-key", r"\b(API-[A-Z0-9]{26})"),
        ("openshift-user-token", r"\b(sha256~[\w-]{43})"),
        ("perplexity-api-key", r"\b(pplx-[a-zA-Z0-9]{48})"),
        ("planetscale-api-token", r"\b(pscale_tkn_(?i)[\w=.-]{32,64})"),
        ("planetscale-oauth-token", r"\b(pscale_oauth_[\w=.-]{32,64})"),
        ("planetscale-password", r"(?i)\b(pscale_pw_[\w=.-]{32,64})"),
        ("postman-api-token", r"\b(PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34})"),
        ("prefect-api-token", r"\b(pnu_[a-zA-Z0-9]{36})"),
        ("pulumi-api-token", r"\b(pul-[a-f0-9]{40})"),
        // SKIPPED: pypi-upload-dedup — duplicate of pypi-upload-token above
        ("readme-api-token", r"\b(rdme_[a-z0-9]{70})"),
        ("rubygems-api-token", r"\b(rubygems_[a-f0-9]{48})"),
        ("scalingo-api-token", r"\b(tk-us-[\w-]{48})"),
        ("sendinblue-api-token", r"\b(xkeysib-[a-f0-9]{64}-(?i)[a-z0-9]{16})"),
        ("sentry-user-token", r"\b(sntryu_[a-f0-9]{64})"),
        ("settlemint-application-access-token", r"\b(sm_aat_[a-zA-Z0-9]{16})"),
        ("settlemint-personal-access-token", r"\b(sm_pat_[a-zA-Z0-9]{16})"),
        ("settlemint-service-access-token", r"\b(sm_sat_[a-zA-Z0-9]{16})"),
        ("shippo-api-token", r"\b(shippo_(?:live|test)_[a-fA-F0-9]{40})"),
        ("shopify-access-token", r"shpat_[a-fA-F0-9]{32}"),
        ("shopify-custom-access-token", r"shpca_[a-fA-F0-9]{32}"),
        ("shopify-private-app-access-token", r"shppa_[a-fA-F0-9]{32}"),
        ("shopify-shared-secret", r"shpss_[a-fA-F0-9]{32}"),
        ("sonar-api-token", r#"(?i)(?:sonar[_.-]?(?:login|token))(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40})"#),
        ("sourcegraph-access-token", r"(?i)\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})"),
        ("twitter-bearer-token", r#"(?i)(?:twitter)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})"#),
        ("typeform-api-token", r#"(?i)(?:typeform)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(tfp_[a-z0-9._=-]{59})"#),
        // simplified: cap repetition to avoid DFA size limit (original {138,300} exceeds 10MB)
        ("vault-batch-token", r"\b(hvb\.[\w\-]{138,200})"),
        ("vault-service-token", r"\b(hvs\.[\w-]{90,120})"),
        ("yandex-api-key", r#"(?i)(?:yandex)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(AQVN[A-Za-z0-9_-]{35,38})"#),
        ("yandex-aws-access-token", r#"(?i)(?:yandex)(?:[\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=)[\s'"=]{0,5}(YC[a-zA-Z0-9_-]{38})"#),

        // --- pii/ssn ---
        ("pii.ssn", r"(?:\d{3}-\d{2}-\d{4})"),

        // --- pii/email ---
        ("pii.email", r"[a-z0-9!#$%&'*+/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"),

        // --- pii/phone ---
        // phones_with_exts: US phone with optional extension
        ("pii.phone", r"(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?"),

        // --- pii/credit-card ---
        ("pii.visa-cc", r"4[0-9]{15}"),
        ("pii.amex-cc", r"3[47][0-9]{13}"),
        ("pii.mastercard-cc", r"(?:5[1-5][0-9]{14}|2(?:2[2-9][1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12})"),
        ("pii.discover-cc", r"6(?:011|5[0-9]{2})[0-9]{12}"),
        ("pii.jcb-cc", r"(?:2131|1800|35[0-9]{3})[0-9]{11}"),

        // --- pii/iban ---
        ("pii.iban", r"[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})"),
    ];

    let mut compiled = Vec::with_capacity(patterns.len());
    for (id, p) in patterns {
        match Regex::new(p) {
            Ok(re) => compiled.push(re),
            Err(e) => eprintln!("SKIPPED pattern {}: {}", id, e),
        }
    }
    compiled
}

fn run_regex(regexes: &[Regex], input: &str) -> usize {
    regexes.iter().map(|re| re.find_iter(input).count()).sum()
}

// --- shannon entropy algorithm ---

/// shannon entropy of a byte slice in bits per byte
fn entropy(window: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in window {
        freq[b as usize] += 1;
    }
    let len = window.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

const WINDOW: usize = 20;
const ENTROPY_THRESHOLD: f64 = 4.5;

fn run_entropy(input: &[u8]) -> usize {
    if input.len() < WINDOW {
        return 0;
    }
    let mut hits = 0usize;
    for start in 0..=(input.len() - WINDOW) {
        if entropy(&input[start..start + WINDOW]) > ENTROPY_THRESHOLD {
            hits += 1;
        }
    }
    hits
}

// --- false positive measurement ---

// measures false positives: runs all regexes against clean corpus samples
// returns: Vec of (pattern_index, sample_index, match_count) for any non-zero match
fn run_fp_measurement(regexes: &[Regex]) -> Vec<(usize, usize, usize)> {
    let mut hits = Vec::new();
    for (si, sample) in FP_CORPUS.iter().enumerate() {
        for (ri, re) in regexes.iter().enumerate() {
            let count = re.find_iter(sample).count();
            if count > 0 {
                hits.push((ri, si, count));
            }
        }
    }
    hits
}

// --- benchmarking harness ---

const ITERATIONS: u64 = 100;

struct BenchResult {
    size_label: &'static str,
    size_bytes: usize,
    algo: &'static str,
    avg_us: f64,
    throughput_mbs: f64,
}

fn bench<F: Fn() -> usize>(f: F, size_bytes: usize) -> (f64, f64) {
    // one warmup run
    let _ = f();

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = f();
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    let avg_us = avg_ns / 1_000.0;
    let throughput = (size_bytes as f64 / (1024.0 * 1024.0)) / (avg_ns / 1e9);
    (avg_us, throughput)
}

fn main() {
    let sizes: &[(&'static str, usize)] = &[
        ("1 KB", 1_024),
        ("10 KB", 10_240),
        ("100 KB", 102_400),
        ("1 MB", 1_048_576),
        ("10 MB", 10_485_760),
    ];

    // build algorithm state once
    let ac = build_aho_corasick();
    let regexes = build_regexes();

    println!("building inputs...");
    let inputs: Vec<(&str, usize, Vec<u8>)> = sizes
        .iter()
        .map(|(label, bytes)| (*label, *bytes, generate_input(*bytes)))
        .collect();

    println!(
        "running {} iterations per (algorithm, size) pair...\n",
        ITERATIONS
    );

    let mut results: Vec<BenchResult> = Vec::new();

    for (label, size_bytes, data) in &inputs {
        // aho-corasick
        {
            let (avg_us, tput) = bench(|| run_aho_corasick(&ac, data), *size_bytes);
            results.push(BenchResult {
                size_label: label,
                size_bytes: *size_bytes,
                algo: "Aho-Corasick",
                avg_us,
                throughput_mbs: tput,
            });
        }

        // regex
        {
            // regex works on &str; generate once (already valid UTF-8 from our generator)
            let text = std::str::from_utf8(data).expect("input is utf8");
            let (avg_us, tput) = bench(|| run_regex(&regexes, text), *size_bytes);
            results.push(BenchResult {
                size_label: label,
                size_bytes: *size_bytes,
                algo: "Regex",
                avg_us,
                throughput_mbs: tput,
            });
        }

        // shannon entropy
        {
            let (avg_us, tput) = bench(|| run_entropy(data), *size_bytes);
            results.push(BenchResult {
                size_label: label,
                size_bytes: *size_bytes,
                algo: "Shannon Entropy",
                avg_us,
                throughput_mbs: tput,
            });
        }
    }

    // print table
    let col_size = 10;
    let col_algo = 17;
    let col_avgt = 14;
    let col_tput = 16;

    let header = format!(
        "{:<col_size$} {:<col_algo$} {:>col_avgt$} {:>col_tput$}",
        "Input Size",
        "Algorithm",
        "Avg Time (µs)",
        "Throughput MB/s",
        col_size = col_size,
        col_algo = col_algo,
        col_avgt = col_avgt,
        col_tput = col_tput,
    );
    let sep = "-".repeat(header.len());

    println!("{}", sep);
    println!("{}", header);
    println!("{}", sep);

    let mut prev_size = "";
    for r in &results {
        if r.size_label != prev_size && prev_size != "" {
            println!("{}", sep);
        }
        prev_size = r.size_label;

        let size_col = if r.algo == "Aho-Corasick" {
            r.size_label
        } else {
            ""
        };
        println!(
            "{:<col_size$} {:<col_algo$} {:>col_avgt$.3} {:>col_tput$.1}",
            size_col,
            r.algo,
            r.avg_us,
            r.throughput_mbs,
            col_size = col_size,
            col_algo = col_algo,
            col_avgt = col_avgt,
            col_tput = col_tput,
        );
    }

    println!("{}", sep);
    println!(
        "\niterations: {}  |  patterns: {}  |  entropy window: {} chars  |  threshold: {}",
        ITERATIONS, CURATED_PATTERN_COUNT, WINDOW, ENTROPY_THRESHOLD
    );

    // false positive measurement
    println!("\n--- false positive measurement ---");
    println!("corpus: {} clean samples", FP_CORPUS.len());
    let fp_hits = run_fp_measurement(&regexes);
    let total_checks = regexes.len() * FP_CORPUS.len();
    println!("total pattern×sample checks: {}", total_checks);
    println!("pattern×sample pairs with >=1 match: {}", fp_hits.len());
    println!("fp rate: {:.1}%", fp_hits.len() as f64 / total_checks as f64 * 100.0);
    println!("\nper-pattern hits on clean corpus:");
    // aggregate by pattern index
    let mut per_pattern = vec![0usize; regexes.len()];
    for (ri, _, count) in &fp_hits {
        per_pattern[*ri] += count;
    }
    for (ri, total) in per_pattern.iter().enumerate() {
        if *total > 0 {
            println!("  pattern[{:02}]: {} match(es)", ri, total);
        }
    }
}
