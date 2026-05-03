# Bleep menu-bar app

macOS menu-bar dashboard for the bleep gateway. Tray icon shows
today's redaction count. Click → menu with summary + "Open
Dashboard…". Dashboard window has summary cards, category /
top-rules charts, and a live tail of redactions as they happen.

Built with [Tauri 2](https://tauri.app/).

## Architecture

```
menu-bar (Tauri)        gateway (bleep-gateway, sibling Cargo crate)
   │                        │
   │  HTTP poll /stats   ◀──┤  axum server  on /tmp/bleep-stats.port
   │                        │
   │  TCP JSONL events   ◀──┤  event_bus    on /tmp/bleep-events.port
   │                        │
   │  spawns as child    ──▶│  process tree
```

The menu-bar app discovers the gateway via two port files in
`/tmp/`:

- `/tmp/bleep-stats.port` — HTTP `/stats`, `/stats/categories`,
  `/stats/rules`, `/health`
- `/tmp/bleep-events.port` — TCP JSONL stream of `ProxyEvent` (same
  one the TUI consumes)

By default the menu-bar app runs in **observe-only mode** — it
displays whatever a separately-running `bleep-gateway` is doing but
does NOT auto-spawn one. Set `BLEEP_SPAWN_GATEWAY=1` to opt into
auto-spawning; on menu-bar quit, the spawned child is killed
(`kill_on_drop = true`).

## Development

From the repo root:

```bash
# build the gateway in release mode (slow first time, fast after)
cargo build --release --bin bleep-gateway

# run the menu-bar app — it will spawn the gateway automatically
cd apps/menu-bar/src-tauri
cargo run
```

If you want to point at a custom gateway binary:

```bash
BLEEP_SPAWN_GATEWAY=1 BLEEP_GATEWAY_BIN=/path/to/bleep-gateway cargo run
```

## Env vars

| Variable | Default | Purpose |
|---|---|---|
| `BLEEP_SPAWN_GATEWAY` | unset | Set to `1`/`true` to make the menu-bar app spawn the gateway as a child process. Without it the app runs in observe-only mode. |
| `BLEEP_GATEWAY_BIN`   | unset | Override the gateway binary path. Only consulted when `BLEEP_SPAWN_GATEWAY` is set. |

## Files

- `src-tauri/src/main.rs` — tray, menu, dashboard window, gateway
  lifecycle, event-bus forwarder
- `src-tauri/tauri.conf.json` — app metadata, CSP, icon paths
- `src-tauri/icons/` — placeholder PNGs (regenerate before shipping)
- `ui/index.html`, `ui/style.css`, `ui/app.js` — vanilla
  HTML/CSS/JS dashboard. No bundler, no framework.
