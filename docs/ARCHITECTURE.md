# Bleep architecture

Top-down map of the components that ship together. Updated 2026-05-03.

## Surfaces

```
                         ┌──────────────────────────────────────────────┐
                         │                  user                         │
                         └────────────┬───────────────────┬─────────────┘
                                      │                   │
                                      ▼                   ▼
                         ┌──────────────────┐    ┌──────────────────┐
                         │   bleep-tui      │    │   menu-bar GUI   │
                         │  (CLI dashboard) │    │   (Tauri app)    │
                         └────────┬─────────┘    └────────┬─────────┘
                                  │                       │
                                  │ TCP JSONL             │ TCP JSONL + HTTP /stats
                                  ▼                       ▼
                                ┌────────────────────────────────────┐
                                │           bleep-gateway            │
                                │   (MITM HTTPS proxy via hudsucker) │
                                │                                    │
                                │   detection → replacement → audit  │
                                └────────────────────────────────────┘
```

Three consumer surfaces of one gateway:

- **bleep-gateway** — MITM proxy. Intercepts HTTPS traffic, scans bodies
  against ~401 detection rules, swaps secrets/PII for realistic fakes,
  forwards. Origin of every redaction event.
- **bleep-tui** — `cargo run --bin bleep-tui` — terminal UI. Subscribes
  to the event_bus over TCP, shows redactions as they happen.
- **menu-bar GUI** — Tauri 2 desktop app at `apps/menu-bar/`. Tray icon
  + dashboard window. Same TCP event_bus + a separate HTTP `/stats`
  endpoint for historical aggregations.

## Workspace layout

```
.
├── Cargo.toml                          ← bleep-gateway crate + workspace root
├── Taskfile.yml                        ← `task <name>` entry points
├── crates/
│   └── bleep-events/                   ← shared wire types (ProxyEvent, RedactedEntry)
│       └── bindings/                   ← auto-generated TS for the JS dashboard
├── src/                                ← bleep-gateway source
│   ├── hudsucker.rs                    ← proxy entry point
│   ├── content_router/                 ← per-content-type handlers
│   ├── detection/                      ← scan logic
│   ├── replacement/                    ← faker logic (realistic by default)
│   ├── stats/                          ← SQLite history
│   ├── stats_server.rs                 ← axum /stats endpoint
│   ├── event_bus.rs                    ← TCP JSONL publisher
│   ├── patterns/                       ← runtime rule loader
│   ├── rule_pipeline.rs                ← lib for the build-rules / curate-rules binaries
│   └── bin/
│       ├── tui.rs                      ← bleep-tui binary
│       ├── build-rules.rs              ← regenerates rules/combined.yaml from vendors
│       └── curate-rules.rs             ← regenerates rules/combined-100.yaml subset
├── apps/
│   └── menu-bar/                       ← Tauri 2 GUI (separate Cargo project)
│       ├── src-tauri/                  ← Rust app shell
│       └── ui/                         ← vanilla HTML/CSS/JS dashboard
└── rules/
    ├── combined.yaml                   ← full 401-rule set (production)
    ├── combined-100.yaml               ← curated dev subset (BLEEP_RULES_FILE)
    ├── EXCLUSIONS.yaml                 ← rules to drop during pipeline
    └── vendor/                         ← upstream sources (gitleaks, NP, SPDB, ha)
```

`apps/menu-bar/src-tauri/` is intentionally **outside** the workspace —
it has a different dep tree (Tauri pulls hundreds of webkit/objc2 crates).
It consumes `crates/bleep-events` via `path = "../../../crates/bleep-events"`.

## Communication channels

The gateway is the single producer; the TUI and GUI are consumers.
Two parallel channels:

| Channel | Producer endpoint | Consumer reads from | Use |
|---|---|---|---|
| **Event bus (live)** | TCP JSONL, port from `/tmp/bleep-events.port` (9191-9200) | TUI: direct TcpStream. GUI: `spawn_event_forwarder` → Tauri IPC `emit("redaction", ...)` | per-event live tail |
| **Stats API (historical)** | HTTP `/stats`, `/stats/categories`, `/stats/rules`, port from `/tmp/bleep-stats.port` (9290-9299) | GUI: poll every 2s | aggregated counts |

Both ports are written to `/tmp/` files at gateway startup. Consumers
discover the gateway by reading those files (no service registry).

The GUI also **embeds the gateway** as a child process when
`BLEEP_SPAWN_GATEWAY=1` (off by default — observe-only is the default).
Lifecycle is bidirectional: `kill_on_drop` from the parent + a
parent-PID watchdog inside the gateway (when launched with
`BLEEP_PARENT_PID` set) so the child dies cleanly even on raw SIGKILL.

## Key invariants

1. **Original matched bytes never reach the event bus or the SQLite DB.**
   Only fake values + metadata. Originals stay only in the JSONL audit
   log on disk.
2. **One source of truth for wire types.** `crates/bleep-events/`. The
   gateway, the TUI, and the GUI all import from there. TS bindings for
   the JS dashboard are auto-generated via `ts-rs`.
3. **Dev/prod rule sets are explicit, never silently swapped.** Runtime
   resolves `BLEEP_RULES_FILE` env var first, falls back to embedded
   `combined.yaml` (full 401). On override-load failure: panic loud.

## Realistic-default mimicry

`src/replacement/replacers.rs` produces format-preserving fakes by
default — same length, same charset, same prefix where applicable. No
"BLEEP" markers in the wire content. Set `BLEEP_VISIBLE_MARKERS=1` to
restore legacy audit-friendly markers (`AKIABLEEP...`, `bleep:bleep@...`)
for log review.

Why: when the LLM downstream is the consumer of the proxied request,
realistic fakes give better answers (the model won't say "your AKIABLEEP
key looks like a placeholder"). The audit trail is a separate channel.

## Common dev tasks

```bash
task run                       # gateway, debug build, 100-rule subset (fast)
task run:full                  # gateway, debug build, full 401 rules
task run:release               # gateway, release build, full rules
task tui                       # the TUI dashboard
task menu-bar                  # the GUI (auto-spawns gateway)
task menu-bar:observe          # the GUI (observe-only)
task menu-bar:stop             # kill GUI + gateway, clean ports
task bindings                  # regen crates/bleep-events/bindings/*.ts
task rules                     # regen rules/combined.yaml from vendors
task test                      # all tests
task lint                      # clippy + fmt check
```

## Pointers

- Wire types: `crates/bleep-events/src/lib.rs`
- TS bindings workflow: see [`apps/menu-bar/README.md`](../apps/menu-bar/README.md)
- Rule pipeline: see [`docs/RULE-PIPELINE.md`](RULE-PIPELINE.md)
- Detection benchmarks: see `docs/benchmarks/`
- Endpoints reference: see [`docs/ENDPOINTS.md`](ENDPOINTS.md)
