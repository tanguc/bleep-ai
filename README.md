<div align="center">

# Bleep

<sub>`Bl██p` — it redacts itself</sub>

<br>

**Intercepts LLM API traffic and substitutes secrets, keys, and PII with realistic look-alike fakes — then restores the originals in the response.**

<br>

[![license](https://img.shields.io/badge/license-MIT-2FD4B3?style=flat-square&labelColor=14161B)](./LICENSE)
[![platform](https://img.shields.io/badge/macOS-Apple%20Silicon%20%7C%20Intel-14161B?style=flat-square&logo=apple&logoColor=white)](#install)
[![built with rust](https://img.shields.io/badge/built%20with-Rust-14161B?style=flat-square&logo=rust&logoColor=E43717)](https://www.rust-lang.org)
[![redaction](https://img.shields.io/badge/redaction-on%20by%20default-2FD4B3?style=flat-square&labelColor=14161B)](#how-it-works)
[![status](https://img.shields.io/badge/status-pre--1.0-F2A33C?style=flat-square&labelColor=14161B)](#)

<br>

`postgres://admin:S3cr3tP%40ss@db.acme-corp.internal`&nbsp; → &nbsp;`postgres://admin:Xq7mK2pNvR%40te@db-94217.internal`
`AKIA4FROMTHEPROD7XYZ`&nbsp; → &nbsp;`AKIA9TQ3RBWELMX2K8VD`&nbsp; · &nbsp;`jane.ops@acme-corp.com`&nbsp; → &nbsp;`lena.park@example.net`

</div>

---

Bleep sits between your machine and the model API. It detects sensitive values
in outbound requests — API keys, tokens, emails, credit cards, connection
strings — and swaps each one for a fake that keeps the original's **shape**: an
`AKIA…` key stays an `AKIA…` key, an email stays a valid-looking email. The model
reasons about the structure just fine; the real value never leaves your machine.
On the way back, the fakes are restored to the originals before your terminal
sees them.

"Transparent" means **zero workflow change** — Bleep wraps the `claude` CLI and
intercepts its TLS, so redaction is on by default with nothing to configure. It
ships as a small gateway binary plus an optional macOS menu-bar dashboard.

> **Scope today:** Bleep MITMs `*.anthropic.com` only. Everything else is
> CONNECT pass-through and is never inspected.

---

## See it in one exchange

<table>
<tr><td>

**1 · You type** &nbsp;<sub>real secrets</sub>

```text
Prod is down. DB is postgres://admin:S3cr3tP%40ss@db.acme-corp.internal:5432/payments,
AWS key AKIA4FROMTHEPROD7XYZ is in the env, ping me at jane.ops@acme-corp.com
```

</td></tr>
</table>

<div align="center"><sub>▼ &nbsp; Bleep scans, substitutes, caches the mapping &nbsp; ▼</sub></div>

<table>
<tr><td>

**2 · `api.anthropic.com` receives** &nbsp;<sub>only look-alikes</sub>

```text
Prod is down. DB is postgres://admin:Xq7mK2pNvR%40te@db-94217.internal:5432/payments,
AWS key AKIA9TQ3RBWELMX2K8VD is in the env, ping me at lena.park@example.net
```

</td></tr>
</table>

| What you wrote | What the provider saw | Rule |
| :-- | :-- | :-- |
| `S3cr3tP%40ss` | `Xq7mK2pNvR%40te` | url-credential |
| `db.acme-corp.internal` | `db-94217.internal` | hostname |
| `AKIA4FROMTHEPROD7XYZ` | `AKIA9TQ3RBWELMX2K8VD` | aws-key |
| `jane.ops@acme-corp.com` | `lena.park@example.net` | email |

<div align="center"><sub>▲ &nbsp; model replies about the fakes — Bleep reverses the mapping &nbsp; ▲</sub></div>

<table>
<tr><td>

**3 · Your terminal shows** &nbsp;<sub>originals restored</sub>

The answer comes back about *your* real database and key. The mapping is cached,
so the same secret always maps to the same fake — multi-turn conversations stay
coherent, and the provider only ever saw the look-alikes.

</td></tr>
</table>

> Nothing was configured. You just ran `claude`.

---

## How it works

```
        your machine                                       provider
  ┌─────────────────────────────────┐
  claude ──▶ bleep ──▶ scrub ────────┼────────────▶ api.anthropic.com
                 ▲                    │
   real values ◀┴─ restore ◀─ fakes ◀─┼────────────◀ streamed response
  └─────────────────────────────────┘
```

1. A local proxy terminates TLS for `*.anthropic.com` using a **per-machine CA**,
   generated on first launch into `~/.bleep/ca/`. The private key never leaves
   your machine and is never shipped — see [Security](#security).
2. Outbound bodies are scanned against ~400 detection rules. Matches are replaced
   with format-preserving fakes; the original→fake mapping is cached in a local
   SQLite dictionary so a given secret always maps to the same fake.
3. The sanitised request is forwarded upstream, and the streamed response is
   de-anonymised back to the real values before your tool sees it.

---

## Install

macOS, Apple Silicon or Intel:

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash
```

This installs `bleep` (wraps `claude`), the `bleep-gateway` binary, `Bleep.app`,
and `bclaude` (a bypass-mode alias that runs `claude` direct, no proxy).

> Piping a remote script to `bash` requires trust — [`install.sh`](./install.sh)
> is self-contained and macOS-only, read it first if you prefer.

<details>
<summary><b>Auto-start on login · enable/disable · uninstall</b></summary>

<br>

Start the gateway automatically at login:

```bash
curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash -s -- --launch-agent
```

Toggle redaction (also available in the menu-bar app's Settings):

```bash
bleep disable    # future claude sessions go direct to the provider
bleep enable     # re-activate
bleep status     # proxy + gateway health + CA path
```

Uninstall:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh) --uninstall
```

User data is preserved on uninstall — the generated CA (`~/.bleep/ca/`), the fake
dictionary (`~/.bleep/bleep-dictionary.db`), and `~/Library/Application Support/bleep`.
Delete those manually for a full wipe.

</details>

---

## Security

Bleep is a TLS-intercepting proxy, so the **CA private key** is the most
sensitive thing on the system — anything that trusts the CA can be impersonated.

- The CA is **generated per machine** on first launch into `~/.bleep/ca/`
  (directory `0700`, key `0600`). It is never baked into the binary, shipped in a
  release, or committed to this repository.
- Client trust is scoped through environment variables (`NODE_EXTRA_CA_CERTS`,
  `BUN_CA_BUNDLE_PATH`, `SSL_CERT_FILE`) pointed at the generated cert — Bleep
  does **not** touch the system keychain.
- The proxy and stats server bind to `127.0.0.1` only.

Found a vulnerability? See [`SECURITY.md`](./SECURITY.md) for private disclosure
— please don't open a public issue for security reports.

---

## Build from source

```bash
# prerequisites: Rust (stable), Task — brew install go-task
git clone https://github.com/tanguc/bleep-ai && cd bleep-ai
git config core.hooksPath .githooks        # conventional-commit checks

task build           # release gateway binary
task run             # gateway on dev ports (no collision with an installed Bleep.app)
task test            # full test suite
task menu-bar        # build + run the menu-bar dashboard (dev)
task install-local   # build + install locally, exactly like the real installer
```

See [`docs/OPERATIONS.md`](./docs/OPERATIONS.md) for implementation notes (CA,
fake dictionary, literal-prefix preservation, MITM scope).

---

## Contributing

Contributions welcome — see [`CONTRIBUTING.md`](./CONTRIBUTING.md). In short:
[Conventional Commits](https://www.conventionalcommits.org/) (enforced by
`.githooks/commit-msg`), `cargo fmt` + `cargo clippy` clean, tests passing.

| type | bump | example |
| :-- | :-- | :-- |
| `feat` | minor | `feat(menu-bar): add database reset buttons` |
| `fix` | patch | `fix(gateway): evict hung connection on :9190` |
| `perf` | patch | `perf(rules): compile regexes in parallel` |
| `feat!` | major | `feat!: drop pre-v1 /redactions response shape` |
| `chore` · `docs` · `refactor` · `test` · `ci` · `build` · `style` | none | |

---

## License

[MIT](./LICENSE) © 2026 Sergen Tanguc.

Bleep bundles detection **pattern data** adapted from gitleaks (MIT),
nosey-parker and detect-secrets (Apache-2.0), and secrets-patterns-db
(**CC BY-SA 4.0** — the derived rule data carries the ShareAlike obligation). Full
attribution in [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md).
