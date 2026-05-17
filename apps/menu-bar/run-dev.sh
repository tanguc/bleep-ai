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

echo "==> kill any stale menu-bar / ui-server instances…"
# match the actual menu-bar binary path, NOT just the name — a previous
# version used `pkill -f bleep-menu-bar` which also matched any shell command
# that mentioned the string (e.g. `tee /tmp/bleep-menu-bar.log`), killing tee
# and breaking the pipe back into this script (SIGPIPE → exit 143).
pkill -f "target/.*/bleep-menu-bar( |$)" 2>/dev/null || true
pkill -f "http.server 1420" 2>/dev/null || true

# Dev mode uses a parallel port range so an installed Bleep.app can keep
# running on :9190 / /tmp/bleep-*.port without colliding.
# Prod: proxy 9190, events 9191-9200, stats 9290-9299, /tmp/bleep-{stats,events}.port
# Dev : proxy 9390, events 9391-9400, stats 9490-9499, /tmp/bleep-{stats,events}-dev.port
# Mirrored in src/devmode.rs (gateway) and apps/menu-bar/src-tauri/src/main.rs.
export BLEEP_DEV=1

# don't touch a gateway that's already running — the user may have started it
# via `task run` and expects the menu-bar to attach to it (gateway_already_running
# check in main.rs). Only clean up the port files if no gateway is listening.
if nc -z 127.0.0.1 9390 2>/dev/null; then
  echo "==> existing dev gateway detected on :9390 — menu-bar will attach to it"
  export BLEEP_SPAWN_GATEWAY=0
else
  echo "==> no dev gateway on :9390 — menu-bar will spawn one"
  rm -f /tmp/bleep-stats-dev.port /tmp/bleep-events-dev.port
  export BLEEP_SPAWN_GATEWAY=1
fi

# serve apps/menu-bar/ui/ over http so devUrl in tauri.conf.json picks up
# disk edits live (Cmd+R in the window reloads without rebuilding cargo).
# debug builds only — release builds still use the embedded frontendDist.
echo "==> starting ui dev server on :1420…"
python3 -m http.server 1420 --directory apps/menu-bar/ui >/tmp/bleep-ui-server.log 2>&1 &
UI_SERVER_PID=$!
trap 'kill $UI_SERVER_PID 2>/dev/null || true' EXIT INT TERM

echo "==> running bleep-menu-bar (debug, BLEEP_SPAWN_GATEWAY=${BLEEP_SPAWN_GATEWAY})…"
cd apps/menu-bar/src-tauri
cargo run
