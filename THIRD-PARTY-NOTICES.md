# Third-Party Notices

bleep is licensed under the [MIT License](./LICENSE). It bundles detection
**pattern data** adapted from several upstream projects, and links against
third-party Rust crates. Their licenses are reproduced/attributed below.

The full upstream license texts are retained verbatim under
`rules/vendor/<source>/LICENSE` (and `NOTICE` where provided).

---

## Bundled detection pattern data

bleep's detection rules (`rules/combined.yaml`, `rules/combined-100.yaml`, and
the per-rule data compiled into the binary) are **derived from** the following
sources. Where a source is copyleft (ShareAlike), the derived rule data carries
that source's license — see the per-source notes.

### secrets-patterns-db — CC BY-SA 4.0  ⚠️ ShareAlike

- Source: https://github.com/mazen160/secrets-patterns-db
- Author: Mazin Ahmed and secrets-patterns-db contributors
- License: Creative Commons Attribution-ShareAlike 4.0 International
  (CC BY-SA 4.0) — https://creativecommons.org/licenses/by-sa/4.0/
- Full text: `rules/vendor/secrets-patterns-db/LICENSE`

**ShareAlike obligation:** the portions of bleep's bundled pattern data that are
adapted from secrets-patterns-db remain licensed under CC BY-SA 4.0. This is a
data/attribution obligation on the *pattern set*; it does not relicense bleep's
source code, which is MIT. Redistributors of the pattern data must preserve this
attribution and the ShareAlike terms.

### gitleaks — MIT

- Source: https://github.com/gitleaks/gitleaks
- Copyright (c) 2019 Zachary Rice
- License: MIT — `rules/vendor/gitleaks/LICENSE`

### nosey-parker — Apache-2.0

- Source: https://github.com/praetorian-inc/noseyparker
- Copyright 2022 Praetorian Security, Inc. <https://praetorian.com>
- License: Apache License 2.0 — `rules/vendor/nosey-parker/LICENSE`
- NOTICE: `rules/vendor/nosey-parker/NOTICE` (reproduced as required by §4(d))

### detect-secrets — Apache-2.0

- Source: https://github.com/Yelp/detect-secrets
- Copyright Yelp, Inc.
- License: Apache License 2.0 — `rules/vendor/detect-secrets/LICENSE`
- NOTICE: `rules/vendor/detect-secrets/NOTICE`

### hand-authored rules

- `rules/vendor/hand-authored/patterns.yaml` is original to this project and is
  covered by bleep's MIT license.

---

## Rust dependencies

bleep links against third-party crates declared in `Cargo.toml` /
`Cargo.lock`. These are permissively licensed (predominantly MIT and/or
Apache-2.0). A machine-checkable license policy is enforced by
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) via `deny.toml`:

```sh
cargo install cargo-deny
cargo deny check licenses
```

To regenerate a complete per-crate license inventory:

```sh
cargo install cargo-about
cargo about generate about.hbs > THIRD-PARTY-RUST.html
```

### Notable forked dependency

- **hudsucker** (MITM proxy core) is consumed from a fork pinned in
  `Cargo.toml` (`[patch.crates-io]`):
  https://github.com/tanguc/hudsucker — upstream
  https://github.com/omjadas/hudsucker is dual-licensed MIT OR Apache-2.0.
  The fork carries a single applied patch (CONNECT pass-through default port)
  and retains the upstream license.
