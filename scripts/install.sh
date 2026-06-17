#!/usr/bin/env bash
# install bleep CLI wrapper — symlinks claude-wrapper.sh into $PREFIX/bin
# usage: ./scripts/install.sh [--prefix /usr/local]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="/usr/local"
WRAPPER="$REPO_DIR/claude-wrapper.sh"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        -h|--help)
            echo "usage: $0 [--prefix DIR]  (default: /usr/local)"
            exit 0 ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
done

BIN_DIR="$PREFIX/bin"
TARGET="$BIN_DIR/bleep"

# sanity checks
if [[ ! -f "$WRAPPER" ]]; then
    echo "error: claude-wrapper.sh not found at $WRAPPER" >&2
    exit 1
fi

if ! command -v claude &>/dev/null; then
    echo "warning: 'claude' CLI not found on PATH — install it before using bleep"
fi

if [[ ! -f "$HOME/.bleep/ca/cert.pem" ]]; then
    echo "note: MITM CA not generated yet — created at ~/.bleep/ca/ on first gateway launch"
fi

chmod +x "$WRAPPER"

# create bin dir if needed (e.g. ~/.local/bin)
mkdir -p "$BIN_DIR"

# remove existing symlink or file
if [[ -L "$TARGET" || -f "$TARGET" ]]; then
    echo "replacing existing $TARGET"
    rm "$TARGET"
fi

ln -s "$WRAPPER" "$TARGET"
echo "installed: $TARGET -> $WRAPPER"
echo ""
echo "usage:"
echo "  bleep                  # start claude via bleep proxy"
echo "  bleep --resume         # resume last session"
echo "  bleep --continue       # continue last conversation"
