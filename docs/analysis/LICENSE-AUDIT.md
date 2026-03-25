# License Audit

**RES-07: Per-source license obligations and Phase 2+ compliance actions**

Produced: 2026-03-25

---

## License Summary Table

| Source | License | Vendoring OK? | Binary Distribution Obligation | Phase 2+ Action Required |
|--------|---------|--------------|-------------------------------|--------------------------|
| gitleaks | MIT | Yes — unrestricted | None | None |
| secrets-patterns-db | CC-BY 4.0 | Yes — attribution required in distributions | Attribution text in binary output or `--licenses` command | Implement attribution before first binary release |
| nosey-parker | Apache-2.0 | Yes — NOTICE file required | Include NOTICE file in release artifacts | Include `rules/vendor/nosey-parker/NOTICE` in release |
| detect-secrets | Apache-2.0 | Yes — NOTICE file required | Include NOTICE file in release artifacts | Include `rules/vendor/detect-secrets/NOTICE` in release |

**Key distinction:** Vendoring into a git repository (Phase 1) has no distribution obligations. Obligations activate when a binary containing the patterns is distributed to end users.

---

## Per-Source Detail

### gitleaks (MIT)

**License file:** `rules/vendor/gitleaks/LICENSE`
**License:** MIT License
**Copyright:** Copyright (c) 2019 Zachary Rice

**Obligations:**
- None for distribution. MIT is fully permissive for binary distribution.
- The license file has been copied to `rules/vendor/gitleaks/LICENSE` and is tracked in git.

**Attribution text (for completeness, not legally required):**
> gitleaks by Zachary Rice (https://github.com/gitleaks/gitleaks), MIT License

**Phase 2+ action:** None required.

---

### secrets-patterns-db (CC-BY 4.0)

**License file:** `rules/vendor/secrets-patterns-db/LICENSE`
**License:** Creative Commons Attribution 4.0 International (CC-BY 4.0)
**Copyright:** Copyright (c) Mazen Azzam

**Obligations:**
- Attribution must be provided in any medium where the patterns (or derived works) are distributed, including binary distributions.
- CC-BY 4.0 does NOT require source disclosure (unlike copyleft licenses).
- CC-BY 4.0 is compatible with commercial use provided attribution is maintained.

**Required attribution text:**
> secrets-patterns-db by Mazen Azzam (https://github.com/mazen160/secrets-patterns-db), licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)

**Attribution mechanism (deferred to Phase 2+):**
The attribution can be satisfied by one of the following mechanisms (decision deferred):
1. `bleep --licenses` command that prints attribution for all bundled pattern sources
2. `bleep --version` output that includes a one-line attribution notice
3. A `LICENSES.txt` file included in the binary distribution archive

The specific mechanism must be implemented before the first binary release that includes these patterns. The attribution text above is the canonical form.

**Phase 2+ action:** Implement one of the attribution mechanisms above. Add a build-time test that verifies the attribution text is present in the binary output.

---

### nosey-parker (Apache-2.0)

**License file:** `rules/vendor/nosey-parker/LICENSE`
**NOTICE file:** `rules/vendor/nosey-parker/NOTICE`
**License:** Apache License, Version 2.0
**Copyright:** Copyright (c) 2022-2025 Praetorian Security, Inc.

**Obligations:**
- The NOTICE file must be reproduced in any distribution of the software. The NOTICE file was copied from the upstream repository during Plan 01-01 vendoring.
- The Apache-2.0 license file must also be included.
- No attribution in binary output required beyond including the NOTICE file in distribution artifacts.

**NOTICE file location:** `rules/vendor/nosey-parker/NOTICE`

**Phase 2+ action:** Include `rules/vendor/nosey-parker/NOTICE` in release artifacts (e.g., as part of a `dist/NOTICES/nosey-parker-NOTICE` in the release archive, or in a combined `THIRD-PARTY-NOTICES.txt`).

---

### detect-secrets (Apache-2.0)

**License file:** `rules/vendor/detect-secrets/LICENSE`
**NOTICE file:** `rules/vendor/detect-secrets/NOTICE`
**License:** Apache License, Version 2.0
**Copyright:** Copyright (c) 2018 Yelp Inc.

**Obligations:** Same as nosey-parker — NOTICE file must be included in distributions.

**Note:** The upstream detect-secrets repository does not include a NOTICE file. A minimal NOTICE file was created during Plan 01-01: `"Apache-2.0 licensed. See LICENSE. Source: https://github.com/Yelp/detect-secrets"`. This satisfies the Apache-2.0 distribution requirement for projects that do not maintain a NOTICE file.

**Phase 2+ action:** Include `rules/vendor/detect-secrets/NOTICE` in release artifacts.

---

## Phase 2+ Action Checklist

The following actions must be completed before any binary distribution of the bleep tool that contains patterns from the vendored sources:

### Before first binary release

- [ ] **[secrets-patterns-db]** Implement `bleep --licenses` (or equivalent attribution mechanism) that outputs the required CC-BY 4.0 attribution text for secrets-patterns-db
- [ ] **[secrets-patterns-db]** Verify attribution text is correct: "secrets-patterns-db by Mazen Azzam (https://github.com/mazen160/secrets-patterns-db), licensed under CC BY 4.0"
- [ ] **[nosey-parker]** Include `rules/vendor/nosey-parker/NOTICE` in binary release artifacts (e.g., `dist/NOTICES/nosey-parker-NOTICE` or combined `THIRD-PARTY-NOTICES.txt`)
- [ ] **[detect-secrets]** Include `rules/vendor/detect-secrets/NOTICE` in binary release artifacts
- [ ] **[gitleaks]** No action required, but including the MIT license in release docs is good practice

### Before each update of vendored patterns

- [ ] Re-check license of the upstream source for any license changes
- [ ] Update VERSION file with new commit SHA and vendoring date
- [ ] Re-run REGEX-COMPAT-REPORT analysis on any new patterns
- [ ] Verify attribution text is still accurate (author/maintainer may change)

---

## Excluded Source: trufflehog

trufflehog was explicitly excluded from vendoring (AGPL-3.0). AGPL requires source disclosure for all linked code in distributed binaries, which is incompatible with the project's commercial trajectory. This exclusion decision is final and documented here for reference.
