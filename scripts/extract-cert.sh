#!/usr/bin/env bash
# stage src/cert.pem into a release-output directory.
# cert.pem is include_str!-baked into the gateway binary (src/hudsucker.rs).
# the installer ships this same file so client TLS stacks trust the proxy CA.
set -euo pipefail
DEST="${1:-dist/staging/lib/bleep/src}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DEST"
cp "$REPO_ROOT/src/cert.pem" "$DEST/cert.pem"
echo "staged cert.pem -> $DEST/cert.pem"
