#!/usr/bin/env bash
# Drive synthetic AI traffic through the bleep gateway by invoking Claude
# Code in non-interactive mode (`claude -p`). Each iteration:
#   1. Generates a developer-shaped prompt containing random synthetic
#      credentials / PII (rule-matching tokens).
#   2. Hands it to claude-wrapper.sh, which already sets HTTPS_PROXY +
#      NODE_EXTRA_CA_CERTS so claude routes through the gateway.
#   3. The gateway redacts before forwarding to Anthropic. Real response
#      comes back; dashboard event bus shows the redaction.
#
# Costs real Anthropic credits. Use COUNT=5 for a quick smoke test.
#
# Usage:
#   ./spam-claude.sh                      # 20 prompts, 1 at a time
#   ./spam-claude.sh 50                   # 50 prompts
#   PARALLEL=4 ./spam-claude.sh 100       # 100 prompts, up to 4 in flight
#
# Env:
#   COUNT     (positional arg 1, default 20)
#   PARALLEL  (default 1; >4 risks rate limits)
#   MODEL     (default haiku — cheapest)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
COUNT="${1:-${COUNT:-20}}"
PARALLEL="${PARALLEL:-1}"
MODEL="${MODEL:-claude-haiku-4-5-20251001}"
WRAPPER="$REPO_ROOT/claude-wrapper.sh"

[[ -x "$WRAPPER" ]] || { echo "missing $WRAPPER" >&2; exit 1; }
command -v claude >/dev/null || { echo "claude not in PATH" >&2; exit 1; }

if ! nc -z 127.0.0.1 9190 2>/dev/null; then
  echo "gateway not on 127.0.0.1:9190 — start with 'task run' or 'task menu-bar'" >&2
  exit 1
fi

# claude is a Bun-bundled binary. NODE_EXTRA_CA_CERTS works for it in
# interactive mode but the non-interactive (-p) path occasionally falls back
# to the system trust store and rejects hudsucker's MITM cert with
# `received fatal alert: BadCertificate`. Setting Bun's own CA env var
# alongside NODE_EXTRA_CA_CERTS makes both runtimes happy.
CERT="$REPO_ROOT/src/cert.pem"
[[ -f "$CERT" ]] || { echo "missing $CERT — restart the gateway to regenerate" >&2; exit 1; }
export NODE_EXTRA_CA_CERTS="$CERT"
export BUN_CA_BUNDLE_PATH="$CERT"
export SSL_CERT_FILE="$CERT"

# ── random fragment generators ────────────────────────────────────────────

rand_alnum()  { LC_ALL=C tr -dc 'a-z0-9'    </dev/urandom | head -c "$1"; }
rand_upper()  { LC_ALL=C tr -dc 'A-Z'       </dev/urandom | head -c "$1"; }
rand_digit()  { LC_ALL=C tr -dc '0-9'       </dev/urandom | head -c "$1"; }

aws_key()    { echo "AKIA$(rand_upper 4)$(rand_alnum 12 | tr 'a-z' 'A-Z')"; }
ghp()        { echo "ghp_$(rand_alnum 36)"; }
stripe_sk()  { echo "sk_live_51$(rand_alnum 24)"; }
ant_key()    { echo "sk-ant-api03-$(rand_alnum 80)"; }
openai_proj(){ echo "sk-proj-$(rand_alnum 48)"; }
slack_bot()  { echo "xoxb-$(rand_digit 10)-$(rand_digit 13)-$(rand_alnum 24)"; }
email()      {
  local n=("alex" "sam" "jamie" "morgan" "riley" "taylor" "jordan" "parker")
  local d=("example.com" "example.org" "fake-co.test" "acme-corp.test")
  echo "${n[$RANDOM % ${#n[@]}]}.$(rand_alnum 4)@${d[$RANDOM % ${#d[@]}]}"
}
phone_us()   { echo "+1 $(rand_digit 3)-$(rand_digit 3)-$(rand_digit 4)"; }
ssn()        { echo "$(rand_digit 3)-$(rand_digit 2)-$(rand_digit 4)"; }
visa()       { echo "4$(rand_digit 3) $(rand_digit 4) $(rand_digit 4) $(rand_digit 4)"; }
pg_url()     { echo "postgres://app:$(rand_alnum 12)@db-$(rand_alnum 4).internal:5432/prod"; }

# ── prompt scenarios — each is a realistic dev question with leaked creds ─

scenario_curl() {
  cat <<EOF
This curl returns 401, can you spot why?

curl -H "Authorization: Bearer $(ghp)" \\
     -H "X-Caller-Email: $(email)" \\
     https://api.github.com/user/repos
EOF
}

scenario_db() {
  cat <<EOF
The pod can't connect to postgres. Connection string in the .env:

DATABASE_URL=$(pg_url)
ADMIN_EMAIL=$(email)

What's the most likely cause?
EOF
}

scenario_logs() {
  cat <<EOF
Customer ticket:

Customer $(email) (phone $(phone_us), card $(visa) on file)
reports inference failing with our key $(stripe_sk).
SSN on the account: $(ssn). Please investigate.

How would you redact this before pasting in a public bug tracker?
EOF
}

scenario_aws() {
  cat <<EOF
Got pinged by gitleaks on a commit. The diff includes:

AWS_ACCESS_KEY_ID=$(aws_key)
AWS_SECRET_ACCESS_KEY=$(rand_alnum 40)
ANTHROPIC_API_KEY=$(ant_key)

What's the right rotation procedure here?
EOF
}

scenario_slack() {
  cat <<EOF
Slack incident channel paste:

[12:04] @alice: deploy failing, rolling back
[12:05] @bob: anyone got the prod webhook? token is $(slack_bot)
[12:06] @alice: contact me at $(email) if it breaks again

What should we do retroactively about that token?
EOF
}

scenario_short() {
  cat <<EOF
Quick question — is "$(openai_proj)" a valid OpenAI key shape? I'm checking
some env files I inherited.
EOF
}

scenarios=(scenario_curl scenario_db scenario_logs scenario_aws scenario_slack scenario_short)

# ── main loop ─────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then D=$'\033[2m'; B=$'\033[1m'; N=$'\033[0m'; else D=""; B=""; N=""; fi

printf '%s==> spamming %s prompts through gateway via claude -p (parallel=%s, model=%s)%s\n\n' \
  "$D" "$COUNT" "$PARALLEL" "$MODEL" "$N"

T0=$(date +%s)
START=$(curl -sS http://127.0.0.1:9290/stats | jq -r '.total // 0')

inflight=0
for i in $(seq 1 "$COUNT"); do
  fn="${scenarios[$RANDOM % ${#scenarios[@]}]}"
  prompt="$($fn)"

  printf '%s[%3d/%s]%s %s scenario=%s\n' "$D" "$i" "$COUNT" "$N" "$(date +%T)" "${fn#scenario_}"

  # claude -p reads the prompt from stdin or as the next arg. Using stdin
  # avoids shell-quoting hell with multi-line prompts. --output-format text
  # for a clean stdout stream that we discard; we're here for the side-
  # effect of the request hitting the proxy.
  printf '%s' "$prompt" | "$WRAPPER" -p --model "$MODEL" --output-format text >/dev/null 2>&1 &

  inflight=$((inflight + 1))
  if (( inflight >= PARALLEL )); then
    wait -n 2>/dev/null || wait
    inflight=$((inflight - 1))
  fi
done
wait

CUR=$(curl -sS http://127.0.0.1:9290/stats | jq -r '.total // 0')
T=$(($(date +%s) - T0))
echo
printf '%sdone in %ss · redactions Δ +%s%s\n' "$B" "$T" "$((CUR - START))" "$N"
