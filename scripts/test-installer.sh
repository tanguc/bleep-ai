#!/usr/bin/env bash
# end-to-end installer smoke test.
# builds a fake release tree under $TMP, points install.sh at it via
# BLEEP_RELEASE_BASE, asserts every artifact landed correctly, then runs
# --uninstall and asserts everything was removed.
set -euo pipefail

log() { echo "[test] $*"; }
die() { echo "[test] FAIL: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$(uname -m | sed 's/arm64/aarch64/')-apple-darwin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

RELEASE_DIR="$TMP/release"
STAGE_GW="$TMP/stage-gw"
STAGE_APP="$TMP/stage-app"
PREFIX="$TMP/prefix"

mkdir -p "$RELEASE_DIR" "$STAGE_GW/bin" "$STAGE_GW/lib/bleep/src" \
         "$STAGE_APP/Bleep.app/Contents/MacOS" "$PREFIX"

# synthetic gateway binary (a shell script wearing the name)
cat > "$STAGE_GW/bin/bleep-gateway" <<'FAKEGW'
#!/usr/bin/env bash
echo "fake gateway pid=$$ args=$*"
FAKEGW
chmod +x "$STAGE_GW/bin/bleep-gateway"

# wrapper script — install.sh expects lib/bleep/bleep-wrapper.sh in the archive
cat > "$STAGE_GW/lib/bleep/bleep-wrapper.sh" <<'FAKEWRAP'
#!/usr/bin/env bash
# fake wrapper for smoke test
exec "$@"
FAKEWRAP
chmod +x "$STAGE_GW/lib/bleep/bleep-wrapper.sh"

# no cert.pem staged — the MITM CA is generated per-machine on first gateway
# launch (src/ca.rs), so it is not part of the release archive.

echo "0.0.0-test" > "$STAGE_GW/.version"

# synthetic Bleep.app
cat > "$STAGE_APP/Bleep.app/Contents/Info.plist" <<PLIST
<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleName</key><string>Bleep</string></dict></plist>
PLIST
cat > "$STAGE_APP/Bleep.app/Contents/MacOS/Bleep" <<'FAKEAPP'
#!/usr/bin/env bash
echo "fake bleep app"
FAKEAPP
chmod +x "$STAGE_APP/Bleep.app/Contents/MacOS/Bleep"

# archives — tar from the staging dirs
tar -C "$STAGE_GW" -czf "$RELEASE_DIR/bleep-gateway-${TARGET}.tar.gz" bin lib .version
tar -C "$STAGE_APP" -czf "$RELEASE_DIR/Bleep.app-${TARGET}.tar.gz" Bleep.app

# checksums (must match install.sh grep pattern: "<hash>  <filename>")
(cd "$RELEASE_DIR" && shasum -a 256 *.tar.gz > checksums.txt)

log "fake release at $RELEASE_DIR"
ls -la "$RELEASE_DIR"

# run installer (--no-launch-agent skips launchctl mutation on the dev machine)
BLEEP_RELEASE_BASE="file://$RELEASE_DIR" \
  bash "$ROOT/install.sh" \
    --prefix="$PREFIX" \
    --version=0.0.0-test \
    --no-launch-agent

# assertions — gateway-side artifacts only (app bundle path varies by permissions)
[ -x "$PREFIX/bin/bleep-gateway" ]                || die "bleep-gateway not installed"
[ -L "$PREFIX/bin/bleep" ]                        || die "bleep is not a symlink"
[ -f "$PREFIX/lib/bleep/bleep-wrapper.sh" ]       || die "wrapper not installed"
[ -f "$PREFIX/lib/bleep/.version" ]               || die ".version not installed"

target="$(readlink "$PREFIX/bin/bleep")"
case "$target" in
  */lib/bleep/bleep-wrapper.sh) ;;
  *) die "symlink target wrong: $target" ;;
esac

grep -q "0.0.0-test" "$PREFIX/lib/bleep/.version" || die ".version content wrong"

log "install assertions passed"

# second run = idempotent upgrade
BLEEP_RELEASE_BASE="file://$RELEASE_DIR" \
  bash "$ROOT/install.sh" \
    --prefix="$PREFIX" \
    --version=0.0.0-test \
    --no-launch-agent
[ -L "$PREFIX/bin/bleep" ] || die "symlink lost after re-run"
log "idempotent re-run passed"

# uninstall
bash "$ROOT/install.sh" --uninstall --prefix="$PREFIX" --no-launch-agent
[ ! -e "$PREFIX/bin/bleep" ]            || die "bleep symlink remained after uninstall"
[ ! -e "$PREFIX/bin/bleep-gateway" ]    || die "gateway remained after uninstall"
[ ! -d "$PREFIX/lib/bleep" ]            || die "lib tree remained after uninstall"
log "uninstall assertions passed"

echo "[test] OK"
