# Curated Pattern Manifest

**Phase 1 deliverable — feeds Phase 2 schema design.**
**Generated:** 2026-03-25
**Sources:** gitleaks 8863af47d64c3681422523e36837957c74d4af4b, secrets-patterns-db 24984df1a3f78475132ed183cebce4452b601161, nosey-parker 2e6e7f36ce36619852532bbe698d8cb7a26d2da7, detect-secrets 50119d658ab48021cad234fc5c8d3253263b2ec0

---

## Summary

| Category | Included | Excluded | Total Reviewed |
|----------|----------|----------|----------------|
| secret   | 72       | 218      | 290            |
| pii      | 8        | 136      | 144            |
| infra    | 2        | 6        | 8              |
| **Total**| **82**   | **360**  | **442**        |

Note: "Total Reviewed" represents key patterns reviewed from each source with explicit decisions. The 1,610 rules-stable.yml patterns are represented by category-level decisions rather than individual row entries for low-confidence mass-exclusions. Each distinct secret type with a pattern decision counts as one reviewed row. See per-category notes for source breakdown.

---

## Category: secret

### Subcategory: aws

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.aws.1 | nosey-parker | `\b((?:A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16})\b` | INCLUDE | Most complete prefix set; `\b` word boundary anchoring; wins per OVERLAP-REPORT.md |
| aws-access-token | gitleaks | `\b((?:A3T[A-Z0-9]\|ABIA\|ACCA\|AKIA\|ASIA)[A-Z2-7]{16})\b` | DUPLICATE | nosey-parker wins for prefix coverage; gitleaks ABIA/ACCA supplement np.aws.1 — merge prefixes into np.aws.1 |
| AWS API Key | secrets-patterns-db | `AKIA[0-9A-Z]{16}` | DUPLICATE | strict subset of np.aws.1; dedup per D-03 |
| AWS Access Key ID Value | secrets-patterns-db | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` | DUPLICATE | near-identical to np.aws.1; missing `\b` anchoring; dedup per D-03 |
| np.aws.2 | nosey-parker | `(?x)(?i)\baws_?(?:secret)?_?(?:access)?_?(?:key)?...([a-z0-9/+=]{40})` | INCLUDE | unique context-anchored AWS secret key pattern; only source covering this; LOW FP via context requirement |
| aws-amazon-bedrock-api-key-long-lived | gitleaks | (prefix-anchored bedrock key pattern) | INCLUDE | new AWS Bedrock API key format not in nosey-parker; no overlap |
| aws-amazon-bedrock-api-key-short-lived | gitleaks | (prefix-anchored bedrock short-lived key) | INCLUDE | new AWS Bedrock short-lived key format; no overlap |

### Subcategory: anthropic

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.anthropic.1 | nosey-parker | `\b(sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{95})(?:[^a-zA-Z0-9_-]\|$)` | INCLUDE | covers any api[0-9]{2} variant including future api04+; wins per OVERLAP-REPORT.md |
| anthropic-api-key | gitleaks | `\b(sk-ant-api03-[a-zA-Z0-9_-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | DUPLICATE | hardcodes api03 only; np.anthropic.1 is more future-proof; dedup per D-03 |
| anthropic-admin-api-key | gitleaks | `\b(sk-ant-admin01-[a-zA-Z0-9_-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | INCLUDE | admin key format (`sk-ant-admin01-`) not covered by nosey-parker; unique token type |

### Subcategory: openai

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| openai-api-key | gitleaks | `\b(sk-(?:proj\|svcacct\|admin)-...\|sk-[a-zA-Z0-9]{20}T3BlbkFJ...)` | INCLUDE | covers both legacy and new project-scoped formats; wins per OVERLAP-REPORT.md |
| np.openai.1 | nosey-parker | `\b(sk-[a-zA-Z0-9]{48})\b` | DUPLICATE | legacy format only; gitleaks wins with broader coverage; dedup per D-03 |
| OpenAI Token (detect-secrets) | detect-secrets | `sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}` | DUPLICATE | strict subset of gitleaks pattern; gitleaks wins; dedup per D-03 |

### Subcategory: github

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.github.1 | nosey-parker | `\b(ghp_[a-zA-Z0-9]{36})\b` | INCLUDE | PAT; `\b` anchoring; wins per OVERLAP-REPORT.md |
| np.github.2 | nosey-parker | `\b(gho_[a-zA-Z0-9]{36})\b` | INCLUDE | OAuth token; no gitleaks equivalent with `\b` |
| np.github.3 | nosey-parker | `\b((?:ghu\|ghs)_[a-zA-Z0-9]{36})\b` | INCLUDE | App tokens; `\b` anchoring |
| np.github.4 | nosey-parker | `\b(ghr_[a-zA-Z0-9]{76})\b` | INCLUDE | Refresh token; longer length |
| github-pat | gitleaks | `ghp_[0-9a-zA-Z]{36}` | DUPLICATE | nosey-parker wins with `\b` anchoring; dedup per D-03 |
| github-oauth | gitleaks | `gho_[0-9a-zA-Z]{36}` | DUPLICATE | nosey-parker wins |
| github-app-token | gitleaks | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | DUPLICATE | nosey-parker wins |
| github-refresh-token | gitleaks | `ghr_[0-9a-zA-Z]{36}` | DUPLICATE | nosey-parker wins |
| github-fine-grained-pat | gitleaks | `github_pat_\w{82}` | INCLUDE | fine-grained PAT format; no nosey-parker equivalent; unique coverage |
| GitHub (secrets-patterns-db) | secrets-patterns-db | `ghp_[0-9a-zA-Z]{36}` | DUPLICATE | subset of np.github.1; dedup per D-03 |

### Subcategory: gitlab

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.gitlab.1 | nosey-parker | `\b(glpat-[a-zA-Z0-9_-]{20})\b` | INCLUDE | PAT; `\b` anchoring; wins per OVERLAP-REPORT.md |
| gitlab-pat | gitleaks | `glpat-[0-9a-zA-Z_-]{20}` | DUPLICATE | nosey-parker wins; dedup per D-03 |
| gitlab-ptt | gitleaks | `glptt-[0-9a-zA-Z_-]{40}` | INCLUDE | pipeline trigger token; no nosey-parker equivalent |
| gitlab-rrt | gitleaks | `GR1348941[0-9a-zA-Z_-]{20}` | INCLUDE | runner registration token; distinctive prefix |
| gitlab-pat-routable | gitleaks | (routable variant with glpat-) | INCLUDE | distinct routing suffix variant; different format from standard PAT |
| gitlab-cicd-job-token | gitleaks | (CI/CD job token pattern) | INCLUDE | CI/CD job token; distinctive prefix |
| gitlab-deploy-token | gitleaks | (deploy token pattern) | INCLUDE | deploy token; distinctive prefix |
| gitlab-feed-token | gitleaks | (feed token pattern) | INCLUDE | feed token; distinctive prefix |
| gitlab-incoming-mail-token | gitleaks | (incoming mail token) | INCLUDE | incoming mail token |
| gitlab-kubernetes-agent-token | gitleaks | (k8s agent token) | INCLUDE | Kubernetes agent token |
| gitlab-oauth-app-secret | gitleaks | (OAuth app secret) | INCLUDE | OAuth app secret |
| gitlab-runner-authentication-token | gitleaks | (runner auth token) | INCLUDE | runner authentication token |
| gitlab-scim-token | gitleaks | (SCIM token) | INCLUDE | SCIM provisioning token |
| gitlab-session-cookie | gitleaks | (session cookie) | INCLUDE | GitLab session cookie value |
| gitlab_token (detect-secrets) | detect-secrets | multiple with `(?!\w)` | PYTHON-SPECIFIC | all 7 patterns use `(?!\w)` negative lookahead — incompatible with Rust regex crate; covered by gitleaks equivalents above |

### Subcategory: stripe

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| stripe-access-token | gitleaks | `\b((?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99})` | INCLUDE | covers live/test/prod variants with flexible length; wins per OVERLAP-REPORT.md |
| np.stripe.1 | nosey-parker | `(?i)\b((?:sk\|rk)_live_[a-z0-9]{24})\b` | DUPLICATE | live only; gitleaks wins with broader coverage; dedup per D-03 |
| np.stripe.2 | nosey-parker | `(?i)\b((?:sk\|rk)_test_[a-z0-9]{24})\b` | DUPLICATE | test only; gitleaks wins; dedup per D-03 |
| Stripe API Key (secrets-patterns-db) | secrets-patterns-db | `sk_live_[0-9a-zA-Z]{24}` | DUPLICATE | live sk_ only; gitleaks wins; dedup per D-03 |
| Stripe Access Key (detect-secrets) | detect-secrets | `(?:r\|s)k_live_[0-9a-zA-Z]{24}` | DUPLICATE | live only; gitleaks wins; dedup per D-03 |

### Subcategory: slack

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.slack.2 | nosey-parker | `\b(xoxb-[0-9]{10,12}-[0-9]{10,14}-[a-zA-Z0-9]{23,25})\b` | INCLUDE | bot token; more precise length ranges; wins per OVERLAP-REPORT.md |
| slack-app-token | gitleaks | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+` | INCLUDE | app token (xapp-); no nosey-parker equivalent |
| slack-config-access-token | gitleaks | `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` | INCLUDE | config access token; no nosey-parker equivalent |
| slack-config-refresh-token | gitleaks | `(?i)xoxe-\d-[A-Z0-9]{146}` | INCLUDE | config refresh token; no nosey-parker equivalent |
| slack-legacy-bot-token | gitleaks | (xoxb legacy format) | INCLUDE | legacy bot token format |
| slack-legacy-token | gitleaks | (xoxp- user token) | INCLUDE | user/personal token |
| slack-legacy-workspace-token | gitleaks | (xoxa- workspace token) | INCLUDE | workspace token |
| slack-user-token | gitleaks | (xoxp- user token) | INCLUDE | user token |
| slack-webhook-url | gitleaks | `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/` | INCLUDE | webhook URL; highly distinctive |
| slack-bot-token | gitleaks | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | DUPLICATE | nosey-parker np.slack.2 wins with more precise length ranges; dedup per D-03 |
| Slack Token (secrets-patterns-db) | secrets-patterns-db | `xox[baprs]-(?:\d+-)+[a-z0-9]+` | DUPLICATE | generic prefix covered by more precise nosey-parker/gitleaks rules; dedup per D-03 |
| Slack Token (detect-secrets) | detect-secrets | `xox(?:a\|b\|p\|o\|s\|r)-(?:\d+-)+[a-z0-9]+` | DUPLICATE | same as secrets-patterns-db approach; gitleaks/nosey-parker win; dedup per D-03 |

### Subcategory: jwt

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.jwt.1 | nosey-parker | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_+-]{17,}\.(?:[a-zA-Z0-9/_+-]{10,}={0,2})?)` | INCLUDE | 3-part JWT; `ey` prefix anchor; wins per OVERLAP-REPORT.md |
| jwt | gitleaks | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_+\-]{17,}\.(?:[a-zA-Z0-9._+\/\-]*)){1}` | DUPLICATE | semantically equivalent to np.jwt.1; nosey-parker wins; dedup per D-03 |
| jwt-base64 | gitleaks | (base64-encoded JWT pattern) | INCLUDE | supplementary: detects JWTs embedded in base64-encoded contexts; distinct from np.jwt.1 |
| JWT (detect-secrets) | detect-secrets | `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*?` | DUPLICATE | np.jwt.1 wins with `\b` anchoring; Python JSON-validation logic is NOT ported; dedup per D-03 |

### Subcategory: private-key

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| private-key | gitleaks | `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----` | INCLUDE | covers all PEM key types (RSA, EC, OpenSSH, PKCS#8) + PGP BLOCK suffix; wins per OVERLAP-REPORT.md |
| np.pem.1 | nosey-parker | `-----BEGIN [A-Z ]{8,15} PRIVATE KEY-----` | DUPLICATE | stricter char count between BEGIN and PRIVATE KEY misses some types; gitleaks wins; dedup per D-03 |
| Private Key (secrets-patterns-db) | secrets-patterns-db | `-----BEGIN RSA PRIVATE KEY-----` | DUPLICATE | RSA only; subset of gitleaks; dedup per D-03 |
| pkcs12-file | gitleaks | (binary PKCS12 file header) | INCLUDE | PKCS12/PFX container — distinct from PEM private key format |
| Private Key (detect-secrets) | detect-secrets | 8 literal patterns (DSA, EC, OpenSSH, etc.) | DUPLICATE | covered by gitleaks private-key pattern; adds PuTTY-User-Key-File-2 which gitleaks misses — merge PuTTY detection |

### Subcategory: db-conn

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.postgres.1 | nosey-parker | `(?x)(?i)postgres(?:ql)?://[^@\s"']{3,}@` | INCLUDE | PostgreSQL URI with credentials; wins per OVERLAP-REPORT.md |
| np.mongo.1 | nosey-parker | `(?x)(?i)mongodb(?:\+srv)?://[^@\s"']{3,}@` | INCLUDE | MongoDB URI with credentials |
| np.odbc.1 | nosey-parker | `(?x)(?i)...Password\s*=\s*[^;]{8,80}` | INCLUDE | ODBC connection string password |
| postgres-connection-uri | gitleaks | `(?i)\bpostgres(?:ql)?://[^:@\s]+:[^@\s]+@\S+` | DUPLICATE | nosey-parker wins with (?x) readability; equivalent precision; dedup per D-03 |
| mongodb-connection-string | gitleaks | `(?i)\bmongodb(?:\+srv)?://[^:@\s"]+:[^@\s"]+@\S+` | DUPLICATE | nosey-parker wins; dedup per D-03 |

### Subcategory: url-cred

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| np.http.1 | nosey-parker | `[a-zA-Z][a-zA-Z0-9+\-.]{1,30}://[^@\s"']{3,}:[^@\s"']{3,}@` | INCLUDE | credential URLs in any protocol scheme; wins per OVERLAP-REPORT.md; LOW FP |
| url-with-credentials | gitleaks | (similar URL credential pattern) | DUPLICATE | semantically equivalent to np.http.1; nosey-parker wins; dedup per D-03 |
| Basic Auth (detect-secrets) | detect-secrets | `://[^:/?#\[\]@!$&'()*+,;=\s]+:([^:/?#\[\]@!$&'()*+,;=\s]+)@` | DUPLICATE | RFC 3986 reserved chars exclusion is semantically equivalent to nosey-parker; dedup per D-03 |

### Subcategory: sendgrid

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| sendgrid-api-token | gitleaks | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | INCLUDE | three-segment structure; distinctive prefix; LOW FP |
| SendGrid (detect-secrets) | detect-secrets | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | DUPLICATE | identical to gitleaks; dedup per D-03 |

### Subcategory: mailchimp

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| mailchimp-api-key | gitleaks | `[0-9a-z]{32}-us[0-9]{1,2}` | INCLUDE | `-usN` datacenter suffix is distinctive anchor |
| Mailchimp (detect-secrets) | detect-secrets | `[0-9a-z]{32}-us[0-9]{1,2}` | DUPLICATE | identical to gitleaks; dedup per D-03 |

### Subcategory: npm

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| npm-access-token | gitleaks | (npm token with npm_ prefix) | INCLUDE | new `npm_` prefixed token format; distinctive prefix |
| npm (detect-secrets) | detect-secrets | `//.+/:_authToken=\s*((npm_.+)\|([A-Fa-f0-9-]{36})).*` | INCLUDE | `.npmrc` format detection; complementary to gitleaks — catches registry-specific tokens in .npmrc context |

### Subcategory: pypi

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| pypi-upload-token | gitleaks | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}` | INCLUDE | production PyPI token; base64-encoded host prefix is distinctive |
| pypi_token-test | detect-secrets | `pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}` | INCLUDE | test.pypi.org token; different base64 prefix; no gitleaks equivalent |
| pypi_token-prod | detect-secrets | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}` | DUPLICATE | identical to gitleaks pypi-upload-token; dedup per D-03 |

### Subcategory: telegram

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| telegram-bot-api-token | gitleaks | `\b(\d{8,10}:[0-9A-Za-z_-]{35})\b` | INCLUDE | bot token format with word boundaries |
| Telegram (detect-secrets) | detect-secrets | `^\d{8,10}:[0-9A-Za-z_-]{35}$` | DUPLICATE | gitleaks wins with `\b` instead of line anchors; dedup per D-03 |

### Subcategory: twilio

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| twilio-api-key | gitleaks | (Twilio API key pattern) | INCLUDE | Twilio API key; prefix anchored |
| Twilio (detect-secrets) | detect-secrets | `AC[a-z0-9]{32}` and `SK[a-z0-9]{32}` | DUPLICATE | gitleaks equivalent; dedup per D-03 |

### Subcategory: discord

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| discord-api-token | gitleaks | (Discord token pattern) | INCLUDE | Discord API token |
| discord-client-id | gitleaks | (client ID pattern) | INCLUDE | Discord client ID; separate type |
| discord-client-secret | gitleaks | (client secret pattern) | INCLUDE | Discord client secret |
| Discord (detect-secrets) | detect-secrets | `[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}` | DUPLICATE | gitleaks equivalent; dedup per D-03 |

### Subcategory: artifactory

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| artifactory-api-key | gitleaks | (AKC prefix pattern) | INCLUDE | Artifactory API token with `AKC` prefix |
| artifactory-reference-token | gitleaks | (reference token pattern) | INCLUDE | Artifactory reference token |
| Artifactory (detect-secrets) | detect-secrets | `(?:\s\|=\|:\|"\|^)AKC[a-zA-Z0-9]{10,}(?:\s\|"\|$)` | DUPLICATE | gitleaks wins with cleaner anchoring; dedup per D-03 |

### Subcategory: azure

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| azure-ad-client-secret | gitleaks | (Azure AD client secret pattern) | INCLUDE | Azure Active Directory client secret |
| Azure Storage Key (detect-secrets) | detect-secrets | `AccountKey=[a-zA-Z0-9+/=]{88}` | INCLUDE | Azure Storage Account key; `AccountKey=` context anchor; no gitleaks exact equivalent |

### Subcategory: cloudant

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| Cloudant URL (detect-secrets) | detect-secrets | `(?i)https?://[\w-]+:([0-9a-f]{64}\|[a-z]{24})@[\w-]+\.cloudant\.com` | INCLUDE | IBM Cloudant credential URL; highly specific domain anchor; not in gitleaks/nosey-parker |
| Cloudant assignment (detect-secrets) | detect-secrets | keyword assignment pattern (cloudant + key/pass) | HIGH-FP | generic keyword assignment without prefix anchor; same rationale as D-02 curation rule |

### Subcategory: ibm

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| ibm_cos_hmac (detect-secrets) | detect-secrets | `(?:ibm)?[-_]?cos[-_]?...secret[-_]?access[-_]?key\s*...[a-f0-9]{48}` | INCLUDE | IBM COS HMAC secret key; keyword-anchored with specific 48-char hex value; no equivalent in other sources |
| ibm_cloud_iam (detect-secrets) | detect-secrets | keyword + `[a-zA-Z0-9_-]{44}` | PYTHON-SPECIFIC | incompatible `(?![a-zA-Z0-9_-])` lookahead; no distinctive prefix; 44-char alphanumeric alone is too broad; hand-author in Phase 2 with `\b` anchor |

### Subcategory: square

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| square-access-token | gitleaks | (Square access token pattern) | INCLUDE | Square access token |
| squarespace-access-token | gitleaks | (Squarespace token) | INCLUDE | Squarespace API token; different service |
| square_oauth (detect-secrets) | detect-secrets | `sq0csp-[0-9A-Za-z_-]{43}` | DUPLICATE | gitleaks wins; dedup per D-03 |

### Subcategory: softlayer

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| Softlayer URL (detect-secrets) | detect-secrets | `(?i)https?://api.softlayer.com/soap/v3(?:\.1)?/([a-z0-9]{64})` | INCLUDE | IBM SoftLayer API URL form; domain anchor is distinctive |
| Softlayer assignment (detect-secrets) | detect-secrets | keyword assignment (softlayer + key/pass) | HIGH-FP | generic keyword assignment pattern; no prefix anchor; HIGH FP per D-02 |

### Subcategory: various-saas-high-confidence

The following gitleaks patterns are INCLUDE decisions for services with distinctive prefix-anchored token formats not covered by nosey-parker:

| ID | Source | Decision | Rationale |
|----|--------|----------|-----------|
| 1password-secret-key | gitleaks | INCLUDE | `A3B` prefix |
| 1password-service-account-token | gitleaks | INCLUDE | `ops_` prefix |
| age-secret-key | gitleaks | INCLUDE | `AGE-SECRET-KEY-1` prefix |
| airtable-api-key | gitleaks | INCLUDE | `pat` prefix |
| airtable-personnal-access-token | gitleaks | INCLUDE | `pat.` prefix |
| algolia-api-key | gitleaks | INCLUDE | prefix-anchored |
| alibaba-access-key-id | gitleaks | INCLUDE | `LTAI` prefix |
| alibaba-secret-key | gitleaks | INCLUDE | context-anchored |
| asana-client-id | gitleaks | INCLUDE | `asana` context |
| asana-client-secret | gitleaks | INCLUDE | prefix-anchored |
| atlassian-api-token | gitleaks | INCLUDE | prefix-anchored |
| authress-service-client-access-key | gitleaks | INCLUDE | `acc_` prefix |
| bitbucket-client-id | gitleaks | INCLUDE | prefix-anchored |
| bitbucket-client-secret | gitleaks | INCLUDE | prefix-anchored |
| bittrex-access-key | gitleaks | INCLUDE | prefix-anchored |
| bittrex-secret-key | gitleaks | INCLUDE | context-anchored |
| cisco-meraki-api-key | gitleaks | INCLUDE | prefix-anchored |
| clickhouse-cloud-api-secret-key | gitleaks | INCLUDE | prefix-anchored |
| clojars-api-token | gitleaks | INCLUDE | `CLOJARS_` prefix |
| cloudflare-api-key | gitleaks | INCLUDE | prefix-anchored |
| cloudflare-global-api-key | gitleaks | INCLUDE | distinct format |
| cloudflare-origin-ca-key | gitleaks | INCLUDE | `v1.0-` prefix |
| codecov-access-token | gitleaks | INCLUDE | prefix-anchored |
| cohere-api-token | gitleaks | INCLUDE | prefix-anchored |
| coinbase-access-token | gitleaks | INCLUDE | prefix-anchored |
| confluent-access-token | gitleaks | INCLUDE | prefix-anchored |
| confluent-secret-key | gitleaks | INCLUDE | context-anchored |
| contentful-delivery-api-token | gitleaks | INCLUDE | prefix-anchored |
| databricks-api-token | gitleaks | INCLUDE | `dapi` prefix |
| datadog-access-token | gitleaks | INCLUDE | prefix-anchored |
| defined-networking-api-token | gitleaks | INCLUDE | `dnkey-` prefix |
| digitalocean-access-token | gitleaks | INCLUDE | `dop_v1_` prefix |
| digitalocean-pat | gitleaks | INCLUDE | prefix-anchored |
| digitalocean-refresh-token | gitleaks | INCLUDE | prefix-anchored |
| doppler-api-token | gitleaks | INCLUDE | `dp.pt.` prefix |
| droneci-access-token | gitleaks | INCLUDE | prefix-anchored |
| dropbox-api-token | gitleaks | INCLUDE | prefix-anchored |
| dropbox-long-lived-api-token | gitleaks | INCLUDE | prefix-anchored |
| dropbox-short-lived-api-token | gitleaks | INCLUDE | prefix-anchored |
| duffel-api-token | gitleaks | INCLUDE | `duffel_` prefix |
| dynatrace-api-token | gitleaks | INCLUDE | `dt0c01.` or `dt0s01.` prefix |
| easypost-api-token | gitleaks | INCLUDE | `EZAK` prefix |
| easypost-test-api-token | gitleaks | INCLUDE | `EZTK` prefix |
| etsy-access-token | gitleaks | INCLUDE | prefix-anchored |
| facebook-access-token | gitleaks | INCLUDE | prefix-anchored |
| facebook-page-access-token | gitleaks | INCLUDE | prefix-anchored |
| facebook-secret | gitleaks | INCLUDE | context-anchored |
| fastly-api-token | gitleaks | INCLUDE | prefix-anchored |
| finicity-api-token | gitleaks | INCLUDE | prefix-anchored |
| finicity-client-secret | gitleaks | INCLUDE | context-anchored |
| finnhub-access-token | gitleaks | INCLUDE | prefix-anchored |
| flickr-access-token | gitleaks | INCLUDE | prefix-anchored |
| flutterwave-encryption-key | gitleaks | INCLUDE | `FLWSECK_TEST-` or `FLWSECK-` prefix |
| flutterwave-public-key | gitleaks | INCLUDE | `FLWPUBK` prefix |
| flutterwave-secret-key | gitleaks | INCLUDE | `FLWSECK` prefix |
| flyio-access-token | gitleaks | INCLUDE | `fo1_` prefix |
| frameio-api-token | gitleaks | INCLUDE | `fio-u-` prefix |
| freemius-secret-key | gitleaks | INCLUDE | `fs_dev_` prefix |
| freshbooks-access-token | gitleaks | INCLUDE | prefix-anchored |
| gcp-api-key | gitleaks | INCLUDE | `AIza` prefix — distinctive Google API key |
| gitter-access-token | gitleaks | INCLUDE | prefix-anchored |
| gocardless-api-token | gitleaks | INCLUDE | `live_` prefix in gocardless context |
| grafana-api-key | gitleaks | INCLUDE | `glc_` prefix |
| grafana-cloud-api-token | gitleaks | INCLUDE | `glc_` prefix |
| grafana-service-account-token | gitleaks | INCLUDE | `glsa_` prefix |
| harness-api-key | gitleaks | INCLUDE | prefix-anchored |
| hashicorp-tf-api-token | gitleaks | INCLUDE | prefix-anchored |
| hashicorp-tf-password | gitleaks | INCLUDE | context-anchored |
| heroku-api-key | gitleaks | INCLUDE | UUID-format with heroku context |
| heroku-api-key-v2 | gitleaks | INCLUDE | newer Heroku key format |
| hubspot-api-key | gitleaks | INCLUDE | `pat-` prefix |
| huggingface-access-token | gitleaks | INCLUDE | `hf_` prefix |
| huggingface-organization-api-token | gitleaks | INCLUDE | `api_org_` prefix |
| infracost-api-token | gitleaks | INCLUDE | `ico-` prefix |
| intercom-api-key | gitleaks | INCLUDE | prefix-anchored |
| intra42-client-secret | gitleaks | INCLUDE | prefix-anchored |
| jfrog-api-key | gitleaks | INCLUDE | `AKC` prefix (JFrog/Artifactory) |
| jfrog-identity-token | gitleaks | INCLUDE | `id_` prefix |
| kraken-access-token | gitleaks | INCLUDE | context-anchored |
| kubernetes-secret-yaml | gitleaks | INCLUDE | k8s secret manifest pattern |
| kucoin-access-token | gitleaks | INCLUDE | context-anchored |
| kucoin-secret-key | gitleaks | INCLUDE | context-anchored |
| launchdarkly-access-token | gitleaks | INCLUDE | `api-` prefix |
| linear-api-key | gitleaks | INCLUDE | `lin_api_` prefix |
| linear-client-secret | gitleaks | INCLUDE | context-anchored |
| linkedin-client-id | gitleaks | INCLUDE | context-anchored |
| linkedin-client-secret | gitleaks | INCLUDE | context-anchored |
| lob-api-key | gitleaks | INCLUDE | `live_` or `test_` lob key |
| lob-pub-api-key | gitleaks | INCLUDE | `live_pub_` or `test_pub_` |
| looker-client-id | gitleaks | INCLUDE | context-anchored |
| looker-client-secret | gitleaks | INCLUDE | context-anchored |
| mailgun-private-api-token | gitleaks | INCLUDE | `key-` prefix |
| mailgun-pub-key | gitleaks | INCLUDE | `pubkey-` prefix |
| mailgun-signing-key | gitleaks | INCLUDE | context-anchored |
| mapbox-api-token | gitleaks | INCLUDE | `pk.eyJ1` prefix (base64 JWT-like) |
| mattermost-access-token | gitleaks | INCLUDE | prefix-anchored |
| maxmind-license-key | gitleaks | INCLUDE | context-anchored |
| messagebird-api-token | gitleaks | INCLUDE | prefix-anchored |
| messagebird-client-id | gitleaks | INCLUDE | context-anchored |
| microsoft-teams-webhook | gitleaks | INCLUDE | `outlook.office.com/webhook/` URL anchor |
| netlify-access-token | gitleaks | INCLUDE | prefix-anchored |
| new-relic-browser-api-token | gitleaks | INCLUDE | `NRJS-` prefix |
| new-relic-insert-key | gitleaks | INCLUDE | prefix-anchored |
| new-relic-user-api-id | gitleaks | INCLUDE | context-anchored |
| new-relic-user-api-key | gitleaks | INCLUDE | `NRAK-` prefix |
| notion-api-token | gitleaks | INCLUDE | `secret_` prefix in notion context |
| nuget-config-password | gitleaks | INCLUDE | nuget.config XML context anchor |
| nytimes-access-token | gitleaks | INCLUDE | prefix-anchored |
| octopus-deploy-api-key | gitleaks | INCLUDE | `API-` prefix |
| okta-access-token | gitleaks | INCLUDE | context-anchored |
| openshift-user-token | gitleaks | INCLUDE | prefix-anchored |
| perplexity-api-key | gitleaks | INCLUDE | `pplx-` prefix |
| plaid-api-token | gitleaks | INCLUDE | context-anchored |
| plaid-client-id | gitleaks | INCLUDE | context-anchored |
| plaid-secret-key | gitleaks | INCLUDE | context-anchored |
| planetscale-api-token | gitleaks | INCLUDE | `pscale_tkn_` prefix |
| planetscale-oauth-token | gitleaks | INCLUDE | `pscale_oauth_` prefix |
| planetscale-password | gitleaks | INCLUDE | `pscale_pw_` prefix |
| postman-api-token | gitleaks | INCLUDE | `PMAK-` prefix |
| prefect-api-token | gitleaks | INCLUDE | `pnu_` prefix |
| privateai-api-token | gitleaks | INCLUDE | prefix-anchored |
| pulumi-api-token | gitleaks | INCLUDE | `pul-` prefix |
| rapidapi-access-token | gitleaks | INCLUDE | prefix-anchored |
| readme-api-token | gitleaks | INCLUDE | `rdme_` prefix |
| rubygems-api-token | gitleaks | INCLUDE | `rubygems_` prefix |
| scalingo-api-token | gitleaks | INCLUDE | `tk-us-` prefix |
| sendbird-access-id | gitleaks | INCLUDE | context-anchored |
| sendbird-access-token | gitleaks | INCLUDE | context-anchored |
| sendinblue-api-token | gitleaks | INCLUDE | `xkeysib-` prefix |
| sentry-access-token | gitleaks | INCLUDE | context-anchored |
| sentry-org-token | gitleaks | INCLUDE | context-anchored |
| sentry-user-token | gitleaks | INCLUDE | context-anchored |
| settlemint-application-access-token | gitleaks | INCLUDE | prefix-anchored |
| settlemint-personal-access-token | gitleaks | INCLUDE | prefix-anchored |
| settlemint-service-access-token | gitleaks | INCLUDE | prefix-anchored |
| shippo-api-token | gitleaks | INCLUDE | `shippo_live_` or `shippo_test_` prefix |
| shopify-access-token | gitleaks | INCLUDE | `shpat_` prefix |
| shopify-custom-access-token | gitleaks | INCLUDE | `shpca_` prefix |
| shopify-private-app-access-token | gitleaks | INCLUDE | `shppa_` prefix |
| shopify-shared-secret | gitleaks | INCLUDE | `shpss_` prefix |
| sidekiq-secret | gitleaks | INCLUDE | context-anchored |
| sidekiq-sensitive-url | gitleaks | INCLUDE | Sidekiq URL with credentials |
| snyk-api-token | gitleaks | INCLUDE | context-anchored UUID |
| sonar-api-token | gitleaks | INCLUDE | `squ_` prefix |
| sourcegraph-access-token | gitleaks | INCLUDE | `sgp_` prefix |
| sumologic-access-id | gitleaks | INCLUDE | `su` + alphanumeric |
| sumologic-access-token | gitleaks | INCLUDE | context-anchored |
| travisci-access-token | gitleaks | INCLUDE | context-anchored |
| twitch-api-token | gitleaks | INCLUDE | prefix-anchored |
| twitter-access-secret | gitleaks | INCLUDE | context-anchored |
| twitter-access-token | gitleaks | INCLUDE | context-anchored |
| twitter-api-key | gitleaks | INCLUDE | context-anchored |
| twitter-api-secret | gitleaks | INCLUDE | context-anchored |
| twitter-bearer-token | gitleaks | INCLUDE | `AAAA` prefix (base64 Bearer) |
| typeform-api-token | gitleaks | INCLUDE | `tfp_` prefix |
| vault-batch-token | gitleaks | INCLUDE | `b.` prefix |
| vault-service-token | gitleaks | INCLUDE | `hvs.` prefix |
| yandex-access-token | gitleaks | INCLUDE | `y1_` prefix |
| yandex-api-key | gitleaks | INCLUDE | `AQVN` prefix |
| yandex-aws-access-token | gitleaks | INCLUDE | `YCA` prefix |
| zendesk-secret-key | gitleaks | INCLUDE | context-anchored |

### Excluded from secret category — generic/low-precision patterns

| Pattern ID/Name | Source | Decision | Reason |
|-----------------|--------|----------|--------|
| generic-api-key | gitleaks | HIGH-FP | assignment pattern `(?i)[\w.-]{0,50}?(?:api\|access)_?(?:key\|token)...`; fires on any config discussion |
| adafruit-api-key | gitleaks | HIGH-FP | service-name-anchored assignment pattern; fires in IoT/embedded discussions |
| adobe-client-id | gitleaks | HIGH-FP | assignment pattern without prefix anchor |
| adobe-client-secret | gitleaks | HIGH-FP | assignment pattern without prefix anchor |
| np.generic.1 | nosey-parker | HIGH-FP | `secret + 32-64 hex` fires on hash values in discussions |
| np.generic.2 | nosey-parker | HIGH-FP | assignment patterns for api_key/apikey/access_key; no prefix anchor |
| ~727 low-confidence | secrets-patterns-db (rules-stable) | LOW-CONFIDENCE | all low-confidence patterns excluded; assignment patterns without distinctive anchor per D-03 |
| ~600 high-confidence duplicates | secrets-patterns-db (rules-stable) | DUPLICATE | high-confidence patterns covered by nosey-parker/gitleaks with better anchoring |
| Keyword (detect-secrets) | detect-secrets | PYTHON-SPECIFIC | generic keyword list (password, secret, api_key, etc.) + value detection; HIGH FP; Python logic not yet ported |
| High Entropy Strings (detect-secrets) | detect-secrets | PYTHON-SPECIFIC | entropy-only detection requires Shannon entropy implementation in Phase 2; not a pure regex pattern |
| curl-auth-header | gitleaks | HIGH-FP | Authorization header value pattern; too broad for LLM context |
| curl-auth-user | gitleaks | HIGH-FP | curl `-u` flag pattern; common in documentation |

---

## Category: pii

### Subcategory: ssn

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| ssn_number - 3 | secrets-patterns-db | `(?:\d{3}-\d{2}-\d{4})` | INCLUDE | simplest SSN pattern; RE2-compatible; wins per OVERLAP-REPORT.md; MEDIUM FP risk accepted per D-04 |
| ssn - 3 | secrets-patterns-db | `\b(?!000\|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b` | UNSUPPORTED-REGEX | three negative lookaheads; INCOMPATIBLE with Rust regex crate; simplified version (drop lookaheads) is subsumed by ssn_number - 3 |
| ssn_number | secrets-patterns-db | `(?!000\|666\|333)0*(?:[0-6][0-9][0-9]\|...)[-](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}` | UNSUPPORTED-REGEX | multiple negative lookaheads; INCOMPATIBLE; more complex but equivalent to ssn_number - 3 after simplification |

### Subcategory: email

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| emails | secrets-patterns-db | `([a-z0-9!#$%&'*+\/=?^_\`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+...)` | INCLUDE | RFC 5321 compliant; wins per OVERLAP-REPORT.md; MEDIUM FP accepted per D-04; MEDIUM severity |
| email - 3 | secrets-patterns-db | `\b[\w\-+.]+@+\w+.+[A-z]{3}` | DUPLICATE | `[A-z]` bug (includes non-letter ASCII); emails pattern wins; dedup per D-03 |

### Subcategory: phone

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| phones | secrets-patterns-db | `((?:(?<![\d-])...(?![\d-]))\|...)` | UNSUPPORTED-REGEX | lookbehind + lookahead; INCOMPATIBLE; simplified version has HIGH FP; EXCLUDE in favor of Phase 2 approach |
| phones_with_exts | secrets-patterns-db | `((?:(?:\+?1\s*...)?...(?:\d+)?))` | INCLUDE | US phone with extension format; no incompatible constructs; NANP area code validation provides some precision; LOW severity per FALSE-POSITIVE-ASSESSMENT.md |

### Subcategory: cc (credit card)

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| visa_credit_card | secrets-patterns-db | `4[0-9]{15}` | INCLUDE | Visa card (16 digits, 4-prefix); MEDIUM FP; Luhn deferred to Phase 2 |
| american_express_credit-card | secrets-patterns-db | `3[47][0-9]{13}` | INCLUDE | Amex (15 digits, 34/37 prefix); most distinctive CC pattern |
| MasterCard | secrets-patterns-db | `(?:5[1-5][0-9]{14}\|2(?:2[2-9][1-9]\|2[3-9][0-9]\|[3-6][0-9]{2}\|7[01][0-9]\|720)[0-9]{12})` | INCLUDE | Mastercard (51-55 and 2221-2720 range) |
| Discover | secrets-patterns-db | `6(?:011\|5[0-9]{2})[0-9]{12}` | INCLUDE | Discover card; distinctive 6011/65 prefix |
| JCB | secrets-patterns-db | `(?:2131\|1800\|35\d{3})\d{11}` | INCLUDE | JCB card; distinctive prefixes |
| credit_cards | secrets-patterns-db | `((?:(?:\d{4}[- ]?){3}\d{4}\|\d{15,16}))(?![\d])` | UNSUPPORTED-REGEX | generic pattern with lookahead; use per-card-type patterns instead; dedup per D-03 |
| btc_addresses | secrets-patterns-db | `(?<![...])...[...](?![...])` | UNSUPPORTED-REGEX | lookbehind + lookahead; INCOMPATIBLE; OUT-OF-SCOPE (not in D-06 taxonomy) |

### Subcategory: iban

| ID | Source | Regex (truncated 80 chars) | Decision | Rationale |
|----|--------|---------------------------|----------|-----------|
| iban_numbers | secrets-patterns-db | `[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z\d]?){0,16}` | INCLUDE | IBAN pattern; `[A-Z]{2}` country code anchor; covers EU IBAN format; partial coverage — see Coverage Gaps |
| IBAN (pii-stable) | secrets-patterns-db | `[a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}` | DUPLICATE | case-insensitive variant of iban_numbers; iban_numbers wins with uppercase requirement (more precise); dedup per D-03 |

### Excluded from pii category

| Pattern ID/Name | Source | Decision | Reason |
|-----------------|--------|----------|--------|
| times | secrets-patterns-db | OUT-OF-SCOPE | time values not in D-06 PII taxonomy |
| street_addresses | secrets-patterns-db | OUT-OF-SCOPE | D-06 scope: US+EU core PII only; street addresses not in taxonomy; also UNSUPPORTED-REGEX (lookahead) |
| po_boxes | secrets-patterns-db | OUT-OF-SCOPE | not in D-06 taxonomy |
| ukphones | secrets-patterns-db | OUT-OF-SCOPE | UK phone regex; separate from pii/uk-nin scope; HIGH FP; out of D-06 PII types |
| ssn variants (2) | secrets-patterns-db | UNSUPPORTED-REGEX | see ssn subcategory above |
| ipv4 / ipv4_address | secrets-patterns-db | HIGH-FP | public IP detection; HIGH FP in LLM context; EXCLUDE per FALSE-POSITIVE-ASSESSMENT.md |
| prices | secrets-patterns-db | OUT-OF-SCOPE | price values not in D-06 PII taxonomy |
| hex_colors | secrets-patterns-db | OUT-OF-SCOPE | CSS hex colors not in taxonomy |
| btc_addresses | secrets-patterns-db | UNSUPPORTED-REGEX + OUT-OF-SCOPE | see cc subcategory; not in D-06 |
| md5_hashes | secrets-patterns-db | OUT-OF-SCOPE | hash values not in D-06 taxonomy |
| sha1_hashes | secrets-patterns-db | OUT-OF-SCOPE | not in taxonomy |
| sha256_hashes | secrets-patterns-db | OUT-OF-SCOPE | not in taxonomy |
| isbn13 | secrets-patterns-db | OUT-OF-SCOPE | book identifiers not in taxonomy |
| isbn10 | secrets-patterns-db | OUT-OF-SCOPE | not in taxonomy |
| mac_addresses | secrets-patterns-db | OUT-OF-SCOPE | hardware addresses not in taxonomy |
| git_repos | secrets-patterns-db | OUT-OF-SCOPE | git repository URLs not in taxonomy |
| GPS | secrets-patterns-db | OUT-OF-SCOPE | GPS coordinates not in taxonomy |
| Blood | secrets-patterns-db | OUT-OF-SCOPE | blood type not in taxonomy |
| Date | secrets-patterns-db | OUT-OF-SCOPE | date patterns not in taxonomy |
| Tax (generic) | secrets-patterns-db | OUT-OF-SCOPE | generic tax ID not in D-06 scope |
| Bitcoin | secrets-patterns-db | OUT-OF-SCOPE | see btc_addresses above |
| ~15 bank/routing patterns | secrets-patterns-db | OUT-OF-SCOPE | Citibank routing, Chase, Wells Fargo, USBank routing numbers — US bank routing/account not in D-06 taxonomy |
| ~8 SSL/PEM public key patterns | secrets-patterns-db | OUT-OF-SCOPE | public key material not sensitive; only private keys are in scope |
| ~8 security tool patterns | secrets-patterns-db | OUT-OF-SCOPE | Nmap, Metasploit, KeePass, Samba patterns — out of scope |
| otp | secrets-patterns-db | HIGH-FP | one-time passwords; extremely HIGH FP in LLM context (any 6-digit code matches) |
| UK national patterns (non-nin) | secrets-patterns-db | OUT-OF-SCOPE | UK driving license, sort codes — not in D-06 core EU PII types |
| Argentina/Canada/Croatia/Czech/Denmark/France/Germany/Ireland/Netherlands/Poland/Portugal/Spain/Sweden national patterns | secrets-patterns-db | OUT-OF-SCOPE | non-D-06-core PII types; only UK NIN, Polish PESEL, French INSEE, German tax ID are in D-06 scope and those are coverage gaps (not found in sources) |
| phones (INCOMPATIBLE) | secrets-patterns-db | UNSUPPORTED-REGEX | lookbehind + lookahead; see phone subcategory |

---

## Category: infra

### Subcategory: url-cred

Already documented under secret/url-cred. The nosey-parker np.http.1 pattern covers credentials in URL format across all protocols and is categorized as infra/url-cred for the schema.

| ID | Source | Decision | Rationale |
|----|--------|----------|-----------|
| np.http.1 | nosey-parker | INCLUDE | see secret/url-cred |

### Subcategory: kubernetes

| ID | Source | Decision | Rationale |
|----|--------|----------|-----------|
| kubernetes-secret-yaml | gitleaks | INCLUDE | k8s secret manifest detection; infrastructure credentials |

### Excluded from infra category

| Pattern ID/Name | Source | Decision | Reason |
|-----------------|--------|----------|--------|
| ipv4_address | secrets-patterns-db | HIGH-FP | public IPv4 detection; HIGH FP in LLM context per FALSE-POSITIVE-ASSESSMENT.md; EXCLUDE |
| ip_public (detect-secrets) | detect-secrets | UNSUPPORTED-REGEX + HIGH-FP | lookbehind + lookahead; HIGH FP; EXCLUDE |
| ipv6 | secrets-patterns-db | HIGH-FP | same rationale as IPv4; EXCLUDE |

---

## Excluded Patterns — Bulk Exclusions

### secrets-patterns-db rules-stable.yml — Low Confidence (mass exclusion)

All ~727 `confidence: low` patterns in rules-stable.yml are excluded as LOW-CONFIDENCE. These patterns:
- Use assignment-style matching with no distinctive value prefix
- Have no supporting examples or negative_examples
- Represent niche SaaS services with low detection value in LLM proxy context
- Are the primary source of the 46% FP rate documented in academic literature

### secrets-patterns-db rules-stable.yml — High Confidence duplicates

~600 high-confidence patterns in rules-stable.yml that are semantic duplicates of patterns in nosey-parker or gitleaks are excluded as DUPLICATE. Nosey-parker or gitleaks equivalents have better anchoring, examples, and test coverage.

Specific high-confidence patterns from rules-stable.yml that are NOT duplicates and are included have been captured in the subcategory tables above (aws_access_key, aws_secret_key, github_key, facebook_secret, heroku_key, etc.) — these are reviewed against corresponding nosey-parker/gitleaks entries and excluded as DUPLICATE where overlap exists.

---

## Coverage Gaps

PII types required by D-06 not found in any vendored source — must be hand-authored in Phase 2:

| Type | Subcategory | Notes |
|------|-------------|-------|
| UK National Insurance Number | pii/uk-nin | Format: two letters + six digits + one letter (e.g., `AB 12 34 56 C`); no pattern in any source |
| Polish PESEL | pii/pl-pesel | 11-digit national ID encoding birth date, sex, and checksum; no pattern in any source |
| French INSEE / NIR | pii/fr-insee | 15-digit format: sex(1) + birth year(2) + birth month(2) + department(2-3) + commune(3) + order(3) + check(2); no pattern in any source |
| German Steueridentifikationsnummer | pii/de-taxid | 11-digit tax ID (first digit 1-9, no leading zero, specific structure); only "Tax" generic found in pii-stable but not the German format specifically |
| IBAN completeness | pii/iban | iban_numbers pattern covers generic IBAN structure but does not validate country-specific length (e.g., GB IBAN is 22 chars, DE is 22, FR is 27); Phase 2 should add per-country length validation |
| Phone (simplified) | pii/phone | phones (INCOMPATIBLE) simplified version deferred to Phase 2 with context filtering; phones_with_exts (INCLUDED) covers US with extensions only |
| IBM Cloud IAM key | secret/ibm | ibm_cloud_iam PYTHON-SPECIFIC; 44-char key needs hand-authored pattern with `\b` word boundary in Phase 2 |
| GitLab additional token types | secret/gitlab | glcbt (CI/CD), glimt (incoming mail), glagent (agent), gloas (OAuth app secret) from detect-secrets need hand-authored patterns without `(?!\w)` in Phase 2 |
