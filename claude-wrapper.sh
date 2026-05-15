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
export NO_PROXY="github.com,api.github.com,*.cloudflare.com,api.cloudflare.com,*.azure.com,*.microsoftonline.com,management.azure.com,login.microsoftonline.com,*.googleapis.com,generativelanguage.googleapis.com,*.miro.com,api.miro.com,proxy.golang.org,sum.golang.org,go.dev,localhost,127.0.0.1"

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

if ! _gateway_running; then
    if [ -x "$_GATEWAY_BIN" ]; then
        echo "[bleep] gateway not running — starting daemon..." >&2
        nohup "$_GATEWAY_BIN" \
            >>/tmp/bleep-gateway.out.log \
            2>>/tmp/bleep-gateway.err.log \
            </dev/null &
        # wait up to 5s for gateway to be ready
        _waited=0
        while [ "$_waited" -lt 5 ]; do
            sleep 1
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

# ── forward signals to the child process ─────────────────────────────────────
cleanup() {
    if [ -n "$CHILD_PID" ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null
        wait "$CHILD_PID" 2>/dev/null
    fi
    exit
}

trap cleanup INT TERM

claude "$@" &
CHILD_PID=$!
wait "$CHILD_PID"
EXIT_CODE=$?
CHILD_PID=
exit $EXIT_CODE
