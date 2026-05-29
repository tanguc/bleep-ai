#!/usr/bin/env bash
unset CLAUDECODE

# Resolve $0 through any chain of symlinks, then take its parent dir.
_SOURCE="$0"
while [ -L "$_SOURCE" ]; do
  _DIR="$(cd -P "$(dirname "$_SOURCE")" && pwd)"
  _SOURCE="$(readlink "$_SOURCE")"
  case "$_SOURCE" in
    /*) ;;
    *) _SOURCE="$_DIR/$_SOURCE" ;;
  esac
done
SCRIPT_DIR="$(cd -P "$(dirname "$_SOURCE")" && pwd)"

# ── logging ──────────────────────────────────────────────────────────────────
# Everything the wrapper decides is appended to /tmp/bleep-wrapper.log so a
# failed/odd launch can be diagnosed after the fact. _say also echoes to the
# terminal (stderr); _wlog is log-file only for the chattier internal steps.
_WLOG=/tmp/bleep-wrapper.log
_wlog() { echo "$(date '+%Y-%m-%dT%H:%M:%S') [$$] $*" >>"$_WLOG" 2>/dev/null || true; }
# colored tag on a tty; plain on pipes/logs so downstream tools stay happy
if [ -t 2 ]; then
    _BLEEP_TAG=$'\033[1;97;41m[bleep]\033[0m'
    _BLEEP_DIM_ON=$'\033[2m'; _BLEEP_DIM_OFF=$'\033[0m'
else
    _BLEEP_TAG='[bleep]'; _BLEEP_DIM_ON=''; _BLEEP_DIM_OFF=''
fi
_say()  { printf '%s %s%s%s\n' "$_BLEEP_TAG" "$_BLEEP_DIM_ON" "$*" "$_BLEEP_DIM_OFF" >&2; _wlog "$*"; }
# indented continuation line (no tag) — for multi-line banners
_line() { printf '        %s%s%s\n' "$_BLEEP_DIM_ON" "$*" "$_BLEEP_DIM_OFF" >&2; _wlog "  $*"; }
# fetch banner metrics with hard timeout — gateway-down fallback shows "—"
_print_banner() {
    local stats_port rules_count stats today week total db oldest_ts since_str
    stats_port="$(cat /tmp/bleep-stats.port 2>/dev/null || echo 9290)"
    # prefer the gateway endpoint (no filesystem dependency); fall back to
    # scanning known on-disk locations if the endpoint is missing (older
    # gateway) or the gateway is down.
    rules_count="$(curl -sf --max-time 0.3 "http://127.0.0.1:${stats_port}/rules/count" 2>/dev/null \
        | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
    if [ -z "$rules_count" ] || [ "$rules_count" = "0" ]; then
        local rules_file
        for rules_file in \
            "$SCRIPT_DIR/rules/combined.yaml" \
            "$SCRIPT_DIR/../share/bleep/rules/combined.yaml" \
            "$HOME/Projects/personal/llmlane-ai-poc-1/rules/combined.yaml" \
            "$HOME/.bleep/rules/combined.yaml" \
            ""; do
            [ -f "$rules_file" ] && break
        done
        rules_count="$(grep -cE '^- id:|^  - id:' "$rules_file" 2>/dev/null || echo 0)"
    fi
    stats="$(curl -sf --max-time 0.3 "http://127.0.0.1:${stats_port}/stats" 2>/dev/null || true)"
    today="$(printf '%s' "$stats" | sed -n 's/.*"today":\([0-9]*\).*/\1/p')"
    week="$(printf '%s'  "$stats" | sed -n 's/.*"last_7d":\([0-9]*\).*/\1/p')"
    total="$(printf '%s' "$stats" | sed -n 's/.*"total":\([0-9]*\).*/\1/p')"
    [ "$rules_count" -gt 0 ] || rules_count="?"

    # DB age: oldest ts. Falls back silently if sqlite3 or DB missing.
    db="$HOME/.bleep/bleep-stats.db"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$db" ]; then
        oldest_ts="$(sqlite3 "$db" 'SELECT MIN(ts) FROM redactions;' 2>/dev/null)"
    fi
    if [ -n "${oldest_ts:-}" ] && [ "$oldest_ts" != "" ]; then
        local now_d oldest_d
        now_d="$(date '+%Y-%m-%d')"
        oldest_d="$(date -r "$oldest_ts" '+%Y-%m-%d' 2>/dev/null)"
        if [ "$now_d" = "$oldest_d" ]; then
            since_str="since $(date -r "$oldest_ts" '+%H:%M') today"
        else
            local days=$(( ( $(date +%s) - oldest_ts ) / 86400 ))
            since_str="for ${days}d (since $(date -r "$oldest_ts" '+%b %-d'))"
        fi
    fi

    _say "█████ engaged"
    _line "hello, friend."
    _line "proxy :9190 is listening. ${rules_count} rules are watching."
    # collapse to one tracking line when buckets haven't diverged yet
    if [ -n "${total:-}" ] && [ "${today:-}" = "${week:-}" ] && [ "${today:-}" = "${total:-}" ]; then
        _line "tracking ${since_str:-since startup} · ${total} secrets stopped."
    else
        _line "24h: ${today:-—} secrets never left your machine."
        _line "7d : ${week:-—}. and counting."
    fi
}
_wlog "==== wrapper invoked: args=[$*] cwd=$(pwd)"

# ── bypass mode ──────────────────────────────────────────────────────────────
# Skip the proxy entirely — useful when bleep is misbehaving or for A/B testing
# claude with vs without redaction. Triggered by either:
#   BLEEP_BYPASS=1 claude ...
#   claude --no-bleep ...   (flag is consumed; not forwarded to claude)
_BLEEP_BYPASS="${BLEEP_BYPASS:-0}"
_FILTERED_ARGS=()
for _arg in "$@"; do
    case "$_arg" in
        --no-bleep|--bleep-bypass) _BLEEP_BYPASS=1 ;;
        *) _FILTERED_ARGS+=("$_arg") ;;
    esac
done
set -- "${_FILTERED_ARGS[@]+"${_FILTERED_ARGS[@]}"}"
unset _FILTERED_ARGS _arg

if [ "$_BLEEP_BYPASS" = "1" ]; then
    _say "bypass mode — proxy disabled, traffic goes direct to anthropic"
    # fall through to claude resolution; skip CA/proxy env + gateway autostart
else

# Trust bleep's CA across every TLS stack any claude subprocess might use:
#   NODE_EXTRA_CA_CERTS — Node / undici / claude's own bundled HTTP client
#   BUN_CA_BUNDLE_PATH  — Bun's native TLS path (claude is a bun-compiled binary)
#   SSL_CERT_FILE       — Python ssl + most OpenSSL-linked code on Linux. Note:
#                         Go on macOS *ignores* SSL_CERT_FILE and reads the
#                         keychain directly, which is why proxy.golang.org is
#                         in NO_PROXY below — the only way to keep Go-based MCP
#                         servers (github-mcp-server uses `go run …`) happy
#                         without trusting the bleep CA in the system keychain.
export NODE_EXTRA_CA_CERTS="$SCRIPT_DIR/src/cert.pem"
export BUN_CA_BUNDLE_PATH="$SCRIPT_DIR/src/cert.pem"
export SSL_CERT_FILE="$SCRIPT_DIR/src/cert.pem"
export HTTP_PROXY=http://localhost:9190
export HTTPS_PROXY=http://localhost:9190
# Only route Anthropic API traffic through bleep. MCP servers (github,
# cloudflare, gemini, azure, etc.) talk directly to their own backends —
# proxying them through bleep adds 9x MITM/scan/buffer overhead with no
# redaction value (the bleep gateway is meant to scrub Anthropic prompts,
# not third-party SaaS auth flows).
# NOTE: the gateway's should_intercept hook decides not to MITM these, but
# hudsucker 0.24's pass-through path errors on CONNECT URIs without a port
# (which is how bun/node clients send them), so we still need this list.
# export NO_PROXY="github.com,api.github.com,*.cloudflare.com,api.cloudflare.com,*.azure.com,*.microsoftonline.com,management.azure.com,login.microsoftonline.com,*.googleapis.com,generativelanguage.googleapis.com,*.miro.com,api.miro.com,proxy.golang.org,sum.golang.org,go.dev,*.1password.com,stone34.sergentanguc.com,localhost,127.0.0.1"

# request logging for the eval pipeline. only consumed by a gateway THIS
# wrapper spawns (see gateway auto-start below) — a child inherits this env.
# the launchd-managed gateway gets the same vars from its plist instead
# (install.sh / ai.bleep.gateway.plist). canonical output:
# /tmp/bleep-requests.jsonl — kept in sync with src/request_logger.rs.
export BLEEP_LOG_REQUESTS=1
export BLEEP_LOG_PATH=/tmp
export BLEEP_ACTIVE=1

# ── status subcommand ────────────────────────────────────────────────────────
if [ "${1:-}" = "status" ]; then
    _stats_port="$(cat /tmp/bleep-stats.port 2>/dev/null || true)"
    _gw_healthy=no
    if [ -n "$_stats_port" ] && curl -sf "http://127.0.0.1:${_stats_port}/health" >/dev/null 2>&1; then
        _gw_healthy=yes
    elif nc -z 127.0.0.1 9190 2>/dev/null; then
        _gw_healthy=yes
    fi
    _stored_claude="$(cat "$SCRIPT_DIR/.claude-path" 2>/dev/null || echo "(not set — using PATH)")"
    cat >&2 <<STATUS
bleep status
  active          : yes (BLEEP_ACTIVE=1 is set for all child processes)
  proxy           : http://localhost:9190
  gateway healthy : ${_gw_healthy}
  real claude     : ${_stored_claude}
  CA cert         : ${SCRIPT_DIR}/src/cert.pem
STATUS
    unset _stats_port _gw_healthy _stored_claude
    exit 0
fi

# ── gateway auto-start ────────────────────────────────────────────────────────

# locate the gateway binary: prefer sibling bin/, then PATH
_GATEWAY_BIN="$(dirname "$SCRIPT_DIR")/bin/bleep-gateway"
if [ ! -x "$_GATEWAY_BIN" ]; then
    _GATEWAY_BIN="$(command -v bleep-gateway 2>/dev/null || true)"
fi

_gateway_running() {
    local stats_port
    stats_port="$(cat /tmp/bleep-stats.port 2>/dev/null || true)"
    if [ -n "$stats_port" ]; then
        curl -sf "http://127.0.0.1:${stats_port}/health" >/dev/null 2>&1 && return 0
    fi
    # fallback: probe the proxy port directly
    nc -z 127.0.0.1 9190 2>/dev/null && return 0
    return 1
}

# kill any hung process holding the proxy port but not responding to health checks
_evict_hung_gateway() {
    nc -z 127.0.0.1 9190 2>/dev/null || return 0   # port free — nothing to do
    local pid
    pid="$(lsof -ti tcp:9190 2>/dev/null | head -1)"
    [ -n "$pid" ] || return 0
    _say "port 9190 held by PID $pid (not healthy) — sending SIGTERM"
    kill -TERM "$pid" 2>/dev/null || true
    local waited=0
    while [ "$waited" -lt 30 ]; do
        sleep 0.1; waited=$((waited + 1))
        nc -z 127.0.0.1 9190 2>/dev/null || { _wlog "hung gateway released port after ${waited}00ms"; return 0; }
    done
    _say "SIGTERM ignored, sending SIGKILL to PID $pid"
    kill -KILL "$pid" 2>/dev/null || true
}

if _gateway_running; then
    _wlog "gateway already running and healthy"
else
    _evict_hung_gateway
    if [ -x "$_GATEWAY_BIN" ]; then
        _say "gateway not running — starting daemon ($_GATEWAY_BIN)"
        nohup "$_GATEWAY_BIN" \
            >>/tmp/bleep-gateway.out.log \
            2>>/tmp/bleep-gateway.err.log \
            </dev/null &
        _wlog "spawned gateway pid=$!"
        # wait up to 5s for gateway to be ready
        _waited=0
        while [ "$_waited" -lt 50 ]; do
            sleep 0.1
            _waited=$((_waited + 1))
            _gateway_running && break
        done
        if _gateway_running; then
            _say "gateway up after ${_waited}00ms"
        else
            _say "warning: gateway did not start in 5s — proceeding anyway"
        fi
    else
        _say "warning: bleep-gateway not found — running without proxy"
    fi
fi
unset _GATEWAY_BIN _waited

fi  # end bypass guard

if [ "$_BLEEP_BYPASS" != "1" ]; then
    _print_banner
fi

# ── forward signals to the child process ─────────────────────────────────────
cleanup() {
    _wlog "received INT/TERM — forwarding to child ${CHILD_PID:-<none>}"
    if [ -n "$CHILD_PID" ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null
        wait "$CHILD_PID" 2>/dev/null
    fi
    exit
}

trap cleanup INT TERM

# Locate the real claude binary.
#
# claude's native installer keeps every version as its own ~200MB executable
# under .../claude/versions/<semver> and does NOT maintain a stable "current"
# symlink (and bleep overwrote the only PATH entry with this wrapper). So a
# path cached at install time goes stale on the very next auto-update.
# Resolve the newest version dynamically on every launch instead.
_CLAUDE_BIN="${BLEEP_CLAUDE_BIN:-}"
_CLAUDE_PATH_FILE="$SCRIPT_DIR/.claude-path"

# pick the highest-versioned executable in claude's versions/ directory.
_resolve_newest_claude() {
    local stored versions_dir newest
    stored="$(cat "$_CLAUDE_PATH_FILE" 2>/dev/null || true)"
    case "$stored" in
        */versions/*) versions_dir="${stored%/versions/*}/versions" ;;
        *)            versions_dir="$HOME/.local/share/claude/versions" ;;
    esac
    [ -d "$versions_dir" ] || return 1
    # entries are bare semver filenames — version-sort, take the last
    newest="$(ls -1 "$versions_dir" 2>/dev/null | sort -V | tail -1)"
    [ -n "$newest" ] && [ -x "$versions_dir/$newest" ] || return 1
    printf '%s' "$versions_dir/$newest"
}

if [ -z "$_CLAUDE_BIN" ]; then
    _CLAUDE_BIN="$(_resolve_newest_claude || true)"
    [ -n "$_CLAUDE_BIN" ] && _wlog "resolved claude via newest-version scan: $_CLAUDE_BIN"
fi
# fall back to the stored path, then PATH, if dynamic resolution found nothing
if [ -z "$_CLAUDE_BIN" ] && [ -f "$_CLAUDE_PATH_FILE" ]; then
    _CLAUDE_BIN="$(cat "$_CLAUDE_PATH_FILE")"
    if [ -x "$_CLAUDE_BIN" ]; then
        _wlog "resolved claude via stored .claude-path: $_CLAUDE_BIN"
    else
        _say "warning: stored claude path '$_CLAUDE_BIN' not executable — falling back to PATH"
        _CLAUDE_BIN=""
    fi
fi
if [ -z "$_CLAUDE_BIN" ]; then
    _CLAUDE_BIN="$(command -v claude 2>/dev/null || true)"
    [ -n "$_CLAUDE_BIN" ] && _wlog "resolved claude via PATH: $_CLAUDE_BIN"
fi
[ -n "$_CLAUDE_BIN" ] || { _say "error: claude binary not found"; exit 1; }
# keep .claude-path fresh so the resign LaunchAgent watches the live version
if [ -n "$_CLAUDE_BIN" ] && [ "$(cat "$_CLAUDE_PATH_FILE" 2>/dev/null || true)" != "$_CLAUDE_BIN" ]; then
    printf '%s' "$_CLAUDE_BIN" > "$_CLAUDE_PATH_FILE" 2>/dev/null \
        && _wlog "updated .claude-path -> $_CLAUDE_BIN" \
        || _wlog "warning: could not write .claude-path"
fi
# Ad-hoc re-sign before exec. claude's auto-updater ships unsigned binaries
# and macOS AMFI SIGKILLs unsigned executables on Apple Silicon (this is the
# `[1] killed claude` you get with no other output). codesign -v on the
# ~200MB binary costs 260–400ms per launch, so we cache the "valid" verdict
# keyed on (path, inode, mtime, size). All four change atomically when the
# auto-updater swaps the binary, so a cache hit means byte-identical to what
# we last verified — no way for an unsigned binary to slip through.
if command -v codesign >/dev/null 2>&1; then
    _CS_CACHE=/tmp/bleep-codesign.cache
    _CS_KEY="$(stat -f '%N|%i|%m|%z' "$_CLAUDE_BIN" 2>/dev/null || true)"
    if [ -n "$_CS_KEY" ] && [ "$(cat "$_CS_CACHE" 2>/dev/null)" = "$_CS_KEY" ]; then
        _wlog "codesign: cache hit — skipping verify ($_CS_KEY)"
    elif codesign -v "$_CLAUDE_BIN" >/dev/null 2>&1; then
        _wlog "codesign: signature valid — caching verdict"
        [ -n "$_CS_KEY" ] && printf '%s' "$_CS_KEY" > "$_CS_CACHE" 2>/dev/null || true
    else
        _wlog "codesign: signature missing/broken — ad-hoc re-signing $_CLAUDE_BIN"
        _SIGN_ERR="$(codesign --force -s - "$_CLAUDE_BIN" 2>&1)" || true
        if codesign -v "$_CLAUDE_BIN" >/dev/null 2>&1; then
            _say "re-signed claude (auto-update left it unsigned)"
            # re-stat: inode/mtime changed when codesign rewrote the binary
            _CS_KEY="$(stat -f '%N|%i|%m|%z' "$_CLAUDE_BIN" 2>/dev/null || true)"
            [ -n "$_CS_KEY" ] && printf '%s' "$_CS_KEY" > "$_CS_CACHE" 2>/dev/null || true
        else
            _say "error: codesign failed — claude would be killed by macOS"
            [ -n "${_SIGN_ERR:-}" ] && _say "  codesign: $_SIGN_ERR"
            _say "  binary: $_CLAUDE_BIN"
            exit 1
        fi
        unset _SIGN_ERR
    fi
    unset _CS_CACHE _CS_KEY
fi
# guard against resolving back to ourselves (would cause an infinite fork loop)
_CLAUDE_BIN_REAL="$(cd -P "$(dirname "$_CLAUDE_BIN")" 2>/dev/null && pwd)/$(basename "$_CLAUDE_BIN")"
if [ "$_CLAUDE_BIN_REAL" = "$_SOURCE" ]; then
    _say "error: claude resolves to this wrapper — store the real claude path by re-running the installer, or set BLEEP_CLAUDE_BIN=/path/to/real/claude"
    exit 1
fi
unset _CLAUDE_BIN_REAL
unset _CLAUDE_PATH_FILE

_wlog "exec claude: $_CLAUDE_BIN"
"$_CLAUDE_BIN" "$@" &
CHILD_PID=$!
wait "$CHILD_PID"
EXIT_CODE=$?
CHILD_PID=
_wlog "claude exited: code=$EXIT_CODE"
exit $EXIT_CODE
