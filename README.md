# Bleep

Bleep is a local MITM proxy that intercepts Claude API traffic, redacts sensitive content from
requests, and forwards the sanitised payloads to Anthropic. It ships as a self-contained macOS
app plus a lightweight gateway binary.

## Install

Requires macOS (Intel or Apple Silicon). One-liner:

<!-- TODO: replace USER with the actual GitHub owner before tagging v0.2.0 -->
```bash
curl -fsSL https://raw.githubusercontent.com/USER/bleep/main/install.sh | bash
```

This installs:

- `bleep` on your PATH (`~/.local/bin/bleep`) — wraps `claude` with the proxy env vars
- `bleep-gateway` binary (`~/.local/bin/bleep-gateway`)
- `Bleep.app` in `/Applications` (or `~/Applications` if the former isn't writable)

### Optional: auto-start the gateway on login

```bash
curl -fsSL https://raw.githubusercontent.com/USER/bleep/main/install.sh | bash -s -- --launch-agent
```

### Uninstall

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/USER/bleep/main/install.sh) --uninstall
```

Or if you already have it locally: `bash ~/path/to/install.sh --uninstall`.

User data (`~/Library/Application Support/bleep`, `~/.local/lib/bleep/src/cert.pem`-derived
keychain trust) is NOT removed automatically — delete those manually if you want a full wipe.

## Development

### Prerequisites

- Rust (stable toolchain)
- [Task](https://taskfile.dev) — `brew install go-task`

### Quick start

```bash
task build      # build release binary
task run        # run gateway (debug)
task test       # run all tests
```

### Release procedure

```bash
task release    # prints the manual release steps
```

### Smoke-test the installer locally

```bash
task test-installer
```
