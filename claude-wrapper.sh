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

# forward signals to the child process
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
