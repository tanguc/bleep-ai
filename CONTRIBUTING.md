# Contributing to Bleep

Thanks for your interest. This guide covers the essentials.

## Getting set up

```bash
git clone https://github.com/tanguc/bleep-ai
cd bleep-ai
git config core.hooksPath .githooks   # required: enables the commit-msg check
```

Prerequisites: Rust (stable), [Task](https://taskfile.dev)
(`brew install go-task`). For releases/commit tooling,
[cocogitto](https://docs.cocogitto.io/) (`brew install cocogitto`).

## Development loop

```bash
task run         # gateway on dev ports (proxy 9390 / stats 9490) — no collision
                 # with an installed Bleep.app on prod ports
task test        # full test suite
task lint        # cargo clippy -D warnings + cargo fmt --check
task fmt         # apply formatting
task menu-bar    # build + run the menu-bar dashboard (dev)
```

Please make sure `task lint` and `task test` are clean before opening a PR.

## Commit messages

All commits MUST be valid [Conventional Commits](https://www.conventionalcommits.org/).
This drives the cocogitto release pipeline, and the local `.githooks/commit-msg`
hook rejects non-conforming messages.

```
<type>[(scope)][!]: <description>
```

`type` is one of: `feat`, `fix`, `perf`, `refactor`, `docs`, `style`, `test`,
`build`, `ci`, `chore`. Use `!` (or a `BREAKING CHANGE:` footer) for breaking
changes.

Do **not** add `Co-Authored-By` trailers or AI-assistant attribution to commits.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Update or add tests for behavioural changes.
- Update docs (`README.md`, `docs/`) when you change user-facing behaviour.
- If you touch the detection rules, run `task rules` to regenerate
  `rules/combined.yaml` and include the regenerated file.

## Detection rules

Rules are vendored from upstream sources and normalised by a build-time
pipeline. Add project-local rules to `rules/custom.yaml`; do not hand-edit
`rules/combined.yaml`. Regenerate with:

```bash
task rules               # full set
cargo run --bin build-rules
```

Bundled pattern data carries upstream licenses (see
[`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md)); secrets-patterns-db is
CC BY-SA 4.0 (ShareAlike). Keep that in mind when adapting rule data.

## Security

Do not report security issues in public PRs or issues — see
[`SECURITY.md`](./SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](./LICENSE).
