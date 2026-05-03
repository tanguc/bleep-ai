#!/usr/bin/env bash
# Build the gateway in release mode (slow first run, fast after) then run
# the menu-bar app in debug mode. The menu-bar app spawns the gateway as
# a child and tears it down on quit.
#
# Usage: ./apps/menu-bar/run-dev.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> building bleep-gateway (release)…"
cargo build --release --bin bleep-gateway

echo "==> kill any stale instances…"
pkill -f bleep-menu-bar 2>/dev/null || true
pkill -f bleep-gateway  2>/dev/null || true
rm -f /tmp/bleep-stats.port /tmp/bleep-events.port

echo "==> running bleep-menu-bar (debug, auto-spawning gateway)…"
cd apps/menu-bar/src-tauri
export BLEEP_SPAWN_GATEWAY=1
exec cargo run
