# Bleep

Bleep is a local MITM proxy that intercepts Claude API traffic, redacts sensitive content from
requests, and forwards the sanitised payloads to Anthropic. It ships as a self-contained macOS
app plus a lightweight gateway binary.

## Install

Requires macOS (Intel or Apple Silicon). One-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash
```

This installs:

- `bleep` on your PATH (`~/.local/bin/bleep`) — wraps `claude` with the proxy env vars
- `bleep-gateway` binary (`~/.local/bin/bleep-gateway`)
- `Bleep.app` in `/Applications` (or `~/Applications` if the former isn't writable)

### Optional: auto-start the gateway on login

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash -s -- --launch-agent
```

### Uninstall

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh) --uninstall
```

Or if you already have it locally: `bash ~/path/to/install.sh --uninstall`.

User data (`~/Library/Application Support/bleep`, `~/.local/lib/bleep/src/cert.pem`-derived
keychain trust) is NOT removed automatically — delete those manually if you want a full wipe.

## Development

### Prerequisites

- Rust (stable toolchain)
- [Task](https://taskfile.dev) — `brew install go-task`
- [cocogitto](https://docs.cocogitto.io/) — `brew install cocogitto` (only needed for commits)

### First-time setup (per clone)

```bash
task install-hooks       # installs cocogitto commit-msg + pre-push hooks
```

### Quick start

```bash
task build               # build release binary
task run                 # run gateway (debug, dev ports — won't collide with installed Bleep.app)
task test                # run all tests
task menu-bar            # build + run the menu-bar dashboard (dev mode)
task install-local       # build release artifacts and install them locally (no GH download)
```

### Commit conventions

All commits MUST be [Conventional Commits](https://www.conventionalcommits.org/). The local hooks
installed by `task install-hooks` enforce this. CI re-checks on every push.

| Type     | Bump  | Example                                           |
|----------|-------|---------------------------------------------------|
| `feat`   | minor | `feat(menu-bar): add database reset buttons`      |
| `fix`    | patch | `fix(gateway): evict hung connection on :9190`    |
| `perf`   | patch | `perf(rules): compile regexes in parallel`        |
| `feat!`  | major | `feat!: drop pre-v1 /redactions response shape`   |
| `chore`  | none  | `chore(deps): bump tauri to 2.4`                  |
| `docs`   | none  | `docs(readme): clarify dev-port partitioning`     |
| `refactor` / `test` / `ci` / `build` / `style` | none | |

### Release procedure

You don't run it — pushing to `main` does. See `task release` for the full description, or
[`.github/workflows/release.yml`](.github/workflows/release.yml) for the implementation.

### Smoke-test the installer locally

```bash
task test-installer
```
