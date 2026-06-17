# Bleep

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](#install)

**Bleep intercepts LLM API traffic and substitutes secrets, keys, and PII with
realistic look-alike fakes, then restores the originals in the response.** It
sits between your machine and the model API, detects sensitive values in
outbound requests (API keys, tokens, emails, credit cards, connection strings,
…), and swaps each one for a fake that keeps the original's shape — an `AKIA…`
key stays an `AKIA…` key, an email stays a valid-looking email. Nothing
sensitive leaves your machine. On the way back, the fakes are restored to the
real values, so the tooling you use never sees the difference.

"Transparent" means zero workflow change: Bleep wraps the `claude` CLI and
intercepts its TLS, so redaction is on by default with nothing to configure. It
ships as a lightweight gateway binary plus an optional macOS menu-bar dashboard.

> **Scope today:** Bleep MITMs `*.anthropic.com` only. All other traffic is
> CONNECT pass-through and is never inspected.

## How it works

1. A local proxy terminates TLS for `*.anthropic.com` using a **per-machine CA**
   that is generated on first launch into `~/.bleep/ca/` (the private key never
   leaves your machine and is never shipped — see [Security](#security)).
2. Outbound request bodies are scanned against ~400 detection rules. Matches are
   replaced with format-preserving fakes; the original→fake mapping is cached in
   a local SQLite dictionary so the same secret always maps to the same fake.
3. The sanitised request is forwarded upstream. The streamed response is
   de-anonymised back to the real values before your tool sees it.

```
claude ──▶ bleep proxy ──[redacted]──▶ api.anthropic.com
                 ▲                              │
                 └────────[de-anonymised]◀──────┘
```

## Install

Requires macOS (Intel or Apple Silicon):

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash
```

This installs:

- `bleep` on your PATH (`~/.local/bin/bleep`) — wraps `claude` with the proxy env
- `bleep-gateway` binary (`~/.local/bin/bleep-gateway`)
- `Bleep.app` in `/Applications` (or `~/Applications` if the former isn't writable)
- `bclaude` — a bypass-mode alias that runs `claude` direct, no proxy

> Piping a remote script to `bash` requires trust. Read
> [`install.sh`](./install.sh) first if you prefer — it is self-contained and
> macOS-only.

### Auto-start the gateway on login

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash -s -- --launch-agent
```

### Enable / disable

```bash
bleep disable    # future claude sessions go direct to anthropic (no redaction)
bleep enable     # re-activate
bleep status     # show proxy + gateway health + CA path
```

The menu-bar app's Settings page has the same toggle.

### Uninstall

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh) --uninstall
```

User data (`~/Library/Application Support/bleep`, the generated CA at
`~/.bleep/ca/`, and the fake dictionary at `~/.bleep/bleep-dictionary.db`) is NOT
removed automatically — delete those manually for a full wipe.

## Build from source

```bash
# prerequisites: Rust (stable), Task (brew install go-task)
git clone https://github.com/tanguc/bleep-ai
cd bleep-ai
git config core.hooksPath .githooks   # conventional-commit checks (contributors)

task build           # release gateway binary
task run             # run gateway on dev ports (won't collide with an installed Bleep.app)
task test            # run the full test suite
task menu-bar        # build + run the menu-bar dashboard in dev mode
task install-local   # build + install locally exactly like the real installer (no GH download)
```

## Security

Bleep is a TLS-intercepting proxy. That makes the **CA private key** the most
sensitive thing on the system: anything that trusts the CA can be impersonated.

- The CA is **generated per machine** on first launch into `~/.bleep/ca/`
  (directory `0700`, key `0600`). It is never baked into the binary, never
  shipped in a release, and never committed to this repository.
- Client trust is scoped via environment variables (`NODE_EXTRA_CA_CERTS`,
  `BUN_CA_BUNDLE_PATH`, `SSL_CERT_FILE`) pointed at the generated cert — Bleep
  does **not** add itself to the system keychain.
- The proxy binds to `127.0.0.1` only.

Found a vulnerability? See [`SECURITY.md`](./SECURITY.md) for responsible
disclosure — please do not open a public issue for security reports.

## Contributing

Contributions welcome. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md). In
short: conventional commits (enforced by `.githooks/commit-msg`), `cargo fmt` +
`cargo clippy` clean, tests passing.

| Type     | Bump  | Example                                           |
|----------|-------|---------------------------------------------------|
| `feat`   | minor | `feat(menu-bar): add database reset buttons`      |
| `fix`    | patch | `fix(gateway): evict hung connection on :9190`    |
| `perf`   | patch | `perf(rules): compile regexes in parallel`        |
| `feat!`  | major | `feat!: drop pre-v1 /redactions response shape`   |
| `chore` / `docs` / `refactor` / `test` / `ci` / `build` / `style` | none | |

## License

[MIT](./LICENSE) © 2026 Sergen Tanguc.

Bleep bundles detection **pattern data** adapted from gitleaks (MIT),
nosey-parker and detect-secrets (Apache-2.0), and secrets-patterns-db
(**CC BY-SA 4.0** — the derived rule data carries the ShareAlike obligation).
See [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md).
