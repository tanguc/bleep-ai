# Rule Pipeline — Developer Workflow

The rule normalization pipeline is **not** a cargo build script. It's a regular library module + CLI binary you invoke explicitly when patterns change.

## TL;DR

```bash
task rules                                  # full regen (401 rules, ~2s)
task rules:dev                              # 30-rule subset (proxy starts <1s)
cargo run --bin build-rules -- --help       # see all flags
cargo run --bin build-rules -- --limit 50   # any custom subset
cargo run --bin build-rules -- --quiet      # suppress progress output
```

After `task rules`, review `git diff rules/combined.yaml` and commit if intended.

## File map

| Path | Role |
|------|------|
| `src/rule_pipeline.rs` | Library module — all parsing, dedup, validation logic. Public entry: `pub fn run(opts: &RunOptions) -> RunResult`. |
| `src/bin/build-rules.rs` | Thin CLI wrapper using clap. |
| `rules/vendor/` | Inputs — vendored upstream files (gitleaks, secrets-patterns-db, nosey-parker, hand-authored). |
| `rules/EXCLUSIONS.yaml` | Skip list — known-bad upstream IDs. |
| `rules/combined.yaml` | **Output (checked in).** Consumed by `src/patterns/mod.rs` via `include_str!`. |
| `rules/patterns-test-fixtures.yaml` | **Output (checked in).** Test fixtures extracted from NP rules. |

## When to run

- After editing any file in `rules/vendor/` or `rules/EXCLUSIONS.yaml`
- After modifying `src/rule_pipeline.rs` itself
- Before committing pattern-related changes

## Why not build.rs?

The pipeline used to be `build.rs` (1550 lines, ran on every `cargo build`). It was refactored because:

1. **Application logic, not a build script.** `build.rs` is meant for tiny build-time tasks (bindings, platform detection). 1550 lines of pattern parsers and validators is application logic that deserves to be testable as normal Rust code.
2. **Tests now run.** The 9 unit tests inside the old `build.rs` were dead code — `cargo test` doesn't run `#[cfg(test)]` inside a build script. Now they're 9 of the 94 lib tests.
3. **`cargo build` is faster and predictable.** No more "wait, did build.rs re-run?" debugging.
4. **Explicit beats implicit.** A regenerated combined.yaml is now a deliberate commit, reviewable in PRs.
5. **Dev iteration.** `--limit N` gives near-instant proxy startup with a small pattern subset for fast iteration.

## Algorithm spec

See `docs/arch/BUILD-PIPELINE.md` (the algorithm is unchanged from the old build.rs implementation).

## Caveat: `--limit` is dev-only

`--limit N` truncates the final ruleset for fast iteration. **Never commit a truncated `combined.yaml`.** The CI / release path always uses the full set.
