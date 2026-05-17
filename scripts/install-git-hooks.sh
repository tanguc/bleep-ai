#!/usr/bin/env bash
# Install cocogitto's commit-msg + pre-push hooks into .git/hooks/.
#
#   commit-msg : runs on `git commit` — rejects non-conventional messages
#                before the commit is recorded, so you re-edit instead of
#                rewriting history later.
#   pre-push   : runs on `git push` — catches anything the commit-msg hook
#                missed (rebases, cherry-picks, --no-verify slips, etc.).
#
# Idempotent: re-running just overwrites.
# Requires `cog` on PATH — see https://docs.cocogitto.io/
set -euo pipefail

if ! command -v cog >/dev/null 2>&1; then
  cat >&2 <<'EOF'
[install-hooks] cocogitto (`cog`) is not on PATH.

Install with one of:
  brew install cocogitto
  cargo install --locked cocogitto

Then re-run: task install-hooks
EOF
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "[install-hooks] must be run from inside the git repo" >&2
  exit 1
}
cd "$REPO_ROOT"

echo "[install-hooks] installing cocogitto commit-msg + pre-push hooks..."
cog install-hook --overwrite commit-msg
cog install-hook --overwrite pre-push

cat <<'EOF'
[install-hooks] done.

Hooks now active:
  .git/hooks/commit-msg  — rejects non-conventional commit messages
  .git/hooks/pre-push    — final check on all commits before push

Bypass (use sparingly):
  git commit --no-verify   # skips commit-msg hook
  git push   --no-verify   # skips pre-push hook

CI (release.yml) re-runs `cog check` regardless, so --no-verify on local
hooks does NOT let bad commits through to a release.
EOF
