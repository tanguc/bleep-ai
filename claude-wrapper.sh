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

export BLEEP_LOG_REQUESTS=1 # TODO remove once in prod
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
    echo "[bleep] port 9190 held by PID $pid (not healthy) — sending SIGTERM" >&2
    kill -TERM "$pid" 2>/dev/null || true
    local waited=0
    while [ "$waited" -lt 30 ]; do
        sleep 0.1; waited=$((waited + 1))
        nc -z 127.0.0.1 9190 2>/dev/null || return 0   # port released
    done
    echo "[bleep] SIGTERM ignored, sending SIGKILL to PID $pid" >&2
    kill -KILL "$pid" 2>/dev/null || true
}

if ! _gateway_running; then
    _evict_hung_gateway
    if [ -x "$_GATEWAY_BIN" ]; then
        echo "[bleep] gateway not running — starting daemon..." >&2
        nohup "$_GATEWAY_BIN" \
            >>/tmp/bleep-gateway.out.log \
            2>>/tmp/bleep-gateway.err.log \
            </dev/null &
        # wait up to 5s for gateway to be ready
        _waited=0
        while [ "$_waited" -lt 50 ]; do
            sleep 0.1
            _waited=$((_waited + 1))
            _gateway_running && break
        done
        if ! _gateway_running; then
            echo "[bleep] warning: gateway did not start in 5s — proceeding anyway" >&2
        fi
    else
        echo "[bleep] warning: bleep-gateway not found — running without proxy" >&2
    fi
fi
unset _GATEWAY_BIN _waited

echo "[bleep] active — proxying via localhost:9190" >&2

# ── forward signals to the child process ─────────────────────────────────────
cleanup() {
    if [ -n "$CHILD_PID" ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null
        wait "$CHILD_PID" 2>/dev/null
    fi
    exit
}

trap cleanup INT TERM

# locate real claude binary: prefer path stored at install time (avoids re-entering
# this wrapper when $PREFIX/bin/claude is itself a symlink to us), then fall back
# to whatever is on PATH.
_CLAUDE_BIN="${BLEEP_CLAUDE_BIN:-}"
_CLAUDE_PATH_FILE="$SCRIPT_DIR/.claude-path"
if [ -z "$_CLAUDE_BIN" ] && [ -f "$_CLAUDE_PATH_FILE" ]; then
    _CLAUDE_BIN="$(cat "$_CLAUDE_PATH_FILE")"
    [ -x "$_CLAUDE_BIN" ] || { echo "[bleep] warning: stored claude path '$_CLAUDE_BIN' not executable — falling back to PATH" >&2; _CLAUDE_BIN=""; }
fi
if [ -z "$_CLAUDE_BIN" ]; then
    _CLAUDE_BIN="$(command -v claude 2>/dev/null || true)"
fi
[ -n "$_CLAUDE_BIN" ] || { echo "[bleep] error: claude binary not found" >&2; exit 1; }
# re-sign only when the binary changed since last sign (mtime-based cache)
if command -v codesign >/dev/null 2>&1; then
    _SIGN_CACHE="/tmp/bleep-codesign-$(echo "$_CLAUDE_BIN" | md5).mtime"
    _BIN_MTIME="$(stat -f '%m' "$_CLAUDE_BIN" 2>/dev/null || echo 0)"
    if [ "$(cat "$_SIGN_CACHE" 2>/dev/null)" != "$_BIN_MTIME" ]; then
        codesign --force -s - "$_CLAUDE_BIN" 2>/dev/null \
            && echo "$_BIN_MTIME" > "$_SIGN_CACHE" \
            || echo "[bleep] warning: codesign failed — claude may be killed by macOS" >&2
    fi
    unset _SIGN_CACHE _BIN_MTIME
fi
# guard against resolving back to ourselves (would cause an infinite fork loop)
_CLAUDE_BIN_REAL="$(cd -P "$(dirname "$_CLAUDE_BIN")" 2>/dev/null && pwd)/$(basename "$_CLAUDE_BIN")"
if [ "$_CLAUDE_BIN_REAL" = "$_SOURCE" ]; then
    echo "[bleep] error: claude resolves to this wrapper — store the real claude path by re-running the installer, or set BLEEP_CLAUDE_BIN=/path/to/real/claude" >&2
    exit 1
fi
unset _CLAUDE_BIN_REAL
unset _CLAUDE_PATH_FILE

"$_CLAUDE_BIN" "$@" &
CHILD_PID=$!
wait "$CHILD_PID"
EXIT_CODE=$?
CHILD_PID=
exit $EXIT_CODE
