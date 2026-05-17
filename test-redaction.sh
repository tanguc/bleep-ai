#!/usr/bin/env bash
# Send a Claude-shaped prompt through the bleep gateway and print BEFORE /
# AFTER / DIFF. Reads redactions from the gateway's TCP event bus (real-time,
# no waiting on upstream HTTP response) so the round-trip stays well under 1s
# regardless of what the destination host does.
#
# How it works:
#   1. Tag the destination URL with a unique marker so we can identify our own
#      request on the event bus (other traffic may be flowing concurrently).
#   2. Open a python listener to /tmp/bleep-events.port and wait for one event
#      whose uri contains our marker.
#   3. POST through the proxy with a short timeout. The body is processed and
#      a Request event is emitted before any upstream forward — we don't care
#      whether the upstream completes.
#   4. Use the (original → fake) pairs from the event to derive AFTER.
#
# Usage:
#   ./test-redaction.sh "my AWS key is AKIAIOSFODNN7EXAMPLE"
#   ./test-redaction.sh                                       # sample prompt
#
# Env:
#   PROXY_PORT (default 9190)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
PROXY_PORT="${PROXY_PORT:-9190}"
CERT="$REPO_ROOT/src/cert.pem"

PROMPT="${*:-Debug help. AWS key AKIAIOSFODNN7EXAMPLE, GitHub ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123, email john.doe@company.com, card 4111111111111111, SSN 123-45-6789.}"

if ! nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; then
  echo "gateway not on 127.0.0.1:$PROXY_PORT — start with 'task run' or 'task menu-bar'" >&2; exit 1
fi
EVENT_PORT_FILE=/tmp/bleep-events.port
[[ -f "$EVENT_PORT_FILE" ]] || { echo "event bus port file missing: $EVENT_PORT_FILE" >&2; exit 1; }
EVENT_PORT=$(cat "$EVENT_PORT_FILE")

for tool in jq curl python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
[[ -f "$CERT" ]] || { echo "cert not found: $CERT" >&2; exit 1; }

MARKER="bleep-test-$(date +%s)-$$-$RANDOM"
EVENT_FILE=$(mktemp -t bleep-event.XXXXXX)
trap 'rm -f "$EVENT_FILE"' EXIT INT TERM

BODY=$(jq -n --arg prompt "$PROMPT" '{
  model: "claude-haiku-4-5-20251001",
  max_tokens: 1,
  messages: [{ role: "user", content: $prompt }]
}')

if [[ -t 1 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; D=$'\033[2m'; N=$'\033[0m'
else
  R=''; G=''; Y=''; B=''; D=''; N=''
fi

printf '%s==> proxy:%s http://127.0.0.1:%s\n' "$D" "$N" "$PROXY_PORT"
printf '%s==> event bus:%s 127.0.0.1:%s (real-time redaction events)\n\n' "$D" "$N" "$EVENT_PORT"

printf '%s── BEFORE ──────────────────────────────────────────────%s\n' "$B" "$N"
printf '%s%s%s\n\n' "$R" "$PROMPT" "$N"

# subscribe to the event bus and wait for the Request event whose URI carries
# our marker. 2s ceiling; bus is local so events arrive in milliseconds.
python3 - "$EVENT_PORT" "$MARKER" <<'PY' >"$EVENT_FILE" 2>/dev/null &
import socket, sys, json
port, marker = int(sys.argv[1]), sys.argv[2]
s = socket.socket(); s.settimeout(2.0)
s.connect(("127.0.0.1", port))
f = s.makefile("r")
for _ in range(200):
    line = f.readline()
    if not line: break
    try: ev = json.loads(line)
    except Exception: continue
    if ev.get("type") == "Request" and marker in (ev.get("uri") or ""):
        print(line, end="")
        break
PY
LISTENER_PID=$!

# tiny pause for the listener to connect before we send
sleep 0.05

# fire curl in the background. We don't care about the upstream response —
# the gateway emits the redaction event the moment it processes the body,
# well before any upstream forward completes (or hangs on a stale pool).
curl -sS --max-time 2 \
  -x "http://127.0.0.1:$PROXY_PORT" \
  --cacert "$CERT" \
  -H "Content-Type: application/json" \
  -o /dev/null \
  -d "$BODY" \
  "https://example.com/$MARKER" >/dev/null 2>&1 &
CURL_PID=$!

# wait for the listener to capture our event (it self-exits on hit). We've
# already got everything we need to render the BEFORE/AFTER once it returns.
wait $LISTENER_PID 2>/dev/null || true
# now let curl drain naturally — killing it mid-forward causes hudsucker to
# log "connection closed before message completed" upstream errors. curl's
# --max-time 2 caps the worst case if the upstream hangs.
wait $CURL_PID    2>/dev/null || true

EVENT=$(cat "$EVENT_FILE")
if [[ -z "$EVENT" ]]; then
  printf '%sno event captured (gateway didn'"'"'t emit one within 2s — check it'"'"'s healthy)%s\n' "$R" "$N"
  exit 1
fi

# pull (original -> fake) pairs out of the event's redacted array
PAIRS=$(printf '%s' "$EVENT" | jq -r '.redacted // [] | map(.original + "\t" + .fake_value) | .[]')

if [[ -z "$PAIRS" ]]; then
  printf '%sno redactions applied — none of the loaded rules matched this prompt%s\n' "$D" "$N"
  printf '%s── AFTER (unchanged) ──────────────────────────────────%s\n' "$B" "$N"
  printf '%s%s%s\n' "$Y" "$PROMPT" "$N"
  exit 0
fi

# longer originals first so substring overlap doesn't corrupt the result
AFTER="$PROMPT"
while IFS=$'\t' read -r orig fake; do
  [[ -z "$orig" ]] && continue
  AFTER="${AFTER//${orig}/${fake}}"
done < <(printf '%s\n' "$PAIRS" | awk -F'\t' '{print length($1)"\t"$0}' | sort -rn | cut -f2-)

printf '%s── AFTER (gateway-forwarded body) ──────────────────────%s\n' "$B" "$N"
printf '%s%s%s\n\n' "$G" "$AFTER" "$N"

printf '%s── REDACTIONS (rule_id: original → fake) ───────────────%s\n' "$B" "$N"
printf '%s' "$EVENT" | jq -r '.redacted[] | "  \(.rule_id): \(.original) → \(.fake_value)"'

printf '\n%s── DIFF ────────────────────────────────────────────────%s\n' "$B" "$N"
diff <(printf '%s\n' "$PROMPT") <(printf '%s\n' "$AFTER") \
  | sed -E "s/^< /${R}- /; s/^> /${G}+ /; s/$/${N}/" || true
