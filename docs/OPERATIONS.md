# Operational notes

Implementation details worth knowing when developing or debugging Bleep.
Contribution workflow lives in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Per-install CA

The MITM CA is generated per machine on first gateway launch into `~/.bleep/ca/`
(`cert.pem`, `key.pem`; dir `0700`, key `0600`). See `src/ca.rs`. It is never
shipped or committed. Delete `~/.bleep/ca/` to force regeneration.

## Persistent fake-dictionary

The fake dictionary lives at `~/.bleep/bleep-dictionary.db` (SQLite, WAL). Every
redaction is cached so the same secret always maps to the same fake across
requests and sessions. On a cache hit `dictionary::lookup_by_original` wins over
minting a fresh fake — so replacer bug-fixes do **not** retroactively apply to
already-cached entries. To invalidate after a replacer change:

- GUI: menu-bar app → Settings → Database → "Reset fake dictionary"
- HTTP: `curl -X POST http://127.0.0.1:$(cat /tmp/bleep-stats.port)/dictionary/reset`
- SQL: `sqlite3 ~/.bleep/bleep-dictionary.db "DELETE FROM dictionary"`

## Literal-prefix preservation

`NormalizedRule.literal_prefix` is extracted from each rule's regex by
`build-rules` and applied by `with_literal_prefix` in `replacers::generate` to
keep vendor heads (`hf_`, `AKIA`, `ghp_`, …) intact through realistic mimicry.
Adding a rule to `rules/custom.yaml` auto-extracts the prefix on the next
`cargo run --bin build-rules`.

## MITM scope

The proxy (hudsucker) only MITMs `*.anthropic.com` (see `src/hudsucker.rs`).
Everything else is CONNECT pass-through and is never inspected or redacted —
relevant when testing with `curl` through the proxy.

## Release pipeline

`release.yml`'s `cog check` is intentionally warn-only (not fatal): a single
non-conventional historical commit must never deadlock releases. The local
`.githooks/commit-msg` hook is the real enforcement point — wire it after a
fresh clone with `git config core.hooksPath .githooks`.
