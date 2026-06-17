# Security Policy

Bleep is a TLS-intercepting redaction proxy. Security is the whole point of the
project, so reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via GitHub's
[private vulnerability reporting](https://github.com/tanguc/bleep-ai/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab).

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof-of-concept if possible),
- the affected version / commit.

You can expect an initial acknowledgement within a few days. Once a fix is
available, we will coordinate disclosure and credit you (if you wish).

## Threat model & design notes

A few properties that are load-bearing for Bleep's security. Reports that
demonstrate a break in any of these are especially valuable:

- **CA private key isolation.** The MITM CA is generated per machine into
  `~/.bleep/ca/` (dir `0700`, key `0600`). It must never be shipped, baked into
  a binary, committed, or transmitted. A build or release that contains a CA
  private key is a critical bug.
- **Loopback-only exposure.** The proxy and the stats/admin HTTP server bind to
  `127.0.0.1`. The stats server exposes redaction *originals* over loopback by
  design (the local dashboard needs them); reachability from off-host is a bug.
- **Redaction completeness.** Secrets/PII that reach the upstream provider
  unredacted (detection misses, streaming edge cases, content-type bypasses) are
  in scope. Include the rule id / payload shape.
- **De-anonymisation correctness.** Fakes leaking into stored state where the
  original was expected, or originals leaking where a fake was expected.

## Scope

In scope: the gateway, the wrapper, the installer, the menu-bar app, and the
detection/replacement pipeline in this repository.

Out of scope: vulnerabilities in upstream dependencies (report those upstream;
we will bump once fixed), and the security of the model provider's own API.

## Supported versions

Bleep is pre-1.0; only the latest release / `main` is supported. Please verify
issues against the latest commit before reporting.
