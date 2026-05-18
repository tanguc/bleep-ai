#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Bleep installer
# Usage:  curl -fsSL https://raw.githubusercontent.com/tanguc/bleep-ai/main/install.sh | bash
#         bash install.sh [flags]
#
# Flags:
#   --uninstall          remove all installed files
#   --local              build from source instead of downloading (requires Rust + cargo-tauri)
#   --prefix=PATH        install root (default: ~/.local)
#   --version=TAG        pin a release tag (default: latest)
#   --repo=OWNER/NAME    override GitHub repo (default: tanguc/bleep-ai)
#   --launch-agent       install LaunchAgent non-interactively (yes)
#   --no-launch-agent    skip LaunchAgent (no)
#   -h, --help           print this help and exit 0
# ============================================================

# --- constants ---
REPO_OWNER_DEFAULT="tanguc"
REPO_NAME_DEFAULT="bleep-ai"
DEFAULT_PREFIX="${HOME}/.local"
INSTALL_LIB_REL="lib/bleep"
LAUNCH_AGENT_LABEL="ai.bleep.gateway"
LAUNCH_AGENT_PLIST_NAME="ai.bleep.gateway.plist"

# --- defaults ---
PREFIX="${DEFAULT_PREFIX}"
VERSION_OVERRIDE=""
REPO_OWNER="${REPO_OWNER_DEFAULT}"
REPO_NAME="${REPO_NAME_DEFAULT}"
LAUNCH_AGENT_CHOICE="ask"   # ask | yes | no
OVERRIDE_CLAUDE=1           # 1=install claude shim | 0=skip
DO_UNINSTALL=0
DO_LOCAL=0

# ============================================================
# Helpers
# ============================================================

log() { printf '[bleep] %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat >&2 <<'EOF'
Usage: bash install.sh [OPTIONS]

Options:
  --uninstall          remove all installed Bleep files
  --local              build from source (requires Rust + cargo-tauri toolchain)
  --prefix=PATH        install root (default: ~/.local)
  --version=TAG        pin a specific release tag
  --repo=OWNER/NAME    override the GitHub repo (default: tanguc/bleep-ai)
  --launch-agent       install LaunchAgent for gateway auto-start on login
  --no-launch-agent    skip LaunchAgent installation
  --no-override-claude skip installing the claude shim (override is on by default)
  -h, --help           show this help

Environment:
  BLEEP_LAUNCH_AGENT=1   same as --launch-agent
  BLEEP_LAUNCH_AGENT=0   same as --no-launch-agent
  BLEEP_OVERRIDE_CLAUDE=0  same as --no-override-claude
EOF
  exit 0
}

# ============================================================
# Flag parsing
# ============================================================

for arg in "$@"; do
  case "$arg" in
    --uninstall)         DO_UNINSTALL=1 ;;
    --local)             DO_LOCAL=1 ;;
    --prefix=*)          PREFIX="${arg#--prefix=}" ;;
    --version=*)         VERSION_OVERRIDE="${arg#--version=}" ;;
    --repo=*)            raw="${arg#--repo=}"; REPO_OWNER="${raw%%/*}"; REPO_NAME="${raw#*/}" ;;
    --launch-agent)      LAUNCH_AGENT_CHOICE="yes" ;;
    --no-launch-agent)   LAUNCH_AGENT_CHOICE="no" ;;
    --no-override-claude) OVERRIDE_CLAUDE=0 ;;
    -h|--help)           usage ;;
    *) die "unknown option: $arg  (try --help)" ;;
  esac
done

# env-var overrides for non-interactive automation
if [ "${BLEEP_LAUNCH_AGENT:-}" = "1" ]; then LAUNCH_AGENT_CHOICE="yes"; fi
if [ "${BLEEP_LAUNCH_AGENT:-}" = "0" ]; then LAUNCH_AGENT_CHOICE="no"; fi
if [ "${BLEEP_OVERRIDE_CLAUDE:-}" = "0" ]; then OVERRIDE_CLAUDE=0; fi

# ============================================================
# Platform guard
# ============================================================

[ "$(uname -s)" = "Darwin" ] || die "this installer is macOS-only (detected: $(uname -s))"

# ============================================================
# Functions
# ============================================================

detect_target() {
  local arch
  arch=$(/usr/bin/uname -m)
  case "$arch" in
    arm64)  echo "aarch64-apple-darwin" ;;
    x86_64) echo "x86_64-apple-darwin" ;;
    *)      die "unsupported arch: $arch" ;;
  esac
}

resolve_version() {
  if [ -n "$VERSION_OVERRIDE" ]; then
    echo "$VERSION_OVERRIDE"
    return
  fi
  local repo="${REPO_OWNER}/${REPO_NAME}"
  local ver
  ver=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
    | grep -m1 '"tag_name":' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$ver" ] || die "could not resolve latest version from GitHub API"
  echo "$ver"
}

download_and_verify() {
  local filename="$1"
  local base_url="$2"
  log "downloading $filename"
  curl -fsSL --retry 3 "${base_url}/${filename}" -o "${TMP}/${filename}"
  local expected actual
  expected=$(grep " ${filename}$" "${TMP}/checksums.txt" | awk '{print $1}')
  [ -n "$expected" ] || die "no checksum entry for $filename in checksums.txt"
  actual=$(shasum -a 256 "${TMP}/${filename}" | awk '{print $1}')
  [ "$expected" = "$actual" ] || die "checksum mismatch for $filename (expected $expected, got $actual)"
  log "$filename: OK"
}

install_gateway_archive() {
  local archive="bleep-gateway-${TARGET}.tar.gz"
  tar -xzf "${TMP}/${archive}" -C "${TMP}/extract"

  mkdir -p "${PREFIX}/bin" "${PREFIX}/${INSTALL_LIB_REL}/src"

  # idempotency: remove stale non-symlink bleep binary from older layout
  if [ -e "${PREFIX}/bin/bleep" ] && [ ! -L "${PREFIX}/bin/bleep" ]; then
    rm -f "${PREFIX}/bin/bleep"
  fi

  mv -f "${TMP}/extract/bin/bleep-gateway"          "${PREFIX}/bin/bleep-gateway"
  mv -f "${TMP}/extract/lib/bleep/bleep-wrapper.sh" "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh"
  mv -f "${TMP}/extract/lib/bleep/src/cert.pem"     "${PREFIX}/${INSTALL_LIB_REL}/src/cert.pem"
  mv -f "${TMP}/extract/.version"                   "${PREFIX}/${INSTALL_LIB_REL}/.version"

  chmod 0755 "${PREFIX}/bin/bleep-gateway" "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh"
  chmod 0644 "${PREFIX}/${INSTALL_LIB_REL}/src/cert.pem"

  ln -sf "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh" "${PREFIX}/bin/bleep"
  log "installed bleep-gateway and wrapper"
}

install_app_bundle() {
  local archive="Bleep.app-${TARGET}.tar.gz"
  local dest_root="/Applications"
  if [ ! -w "$dest_root" ]; then
    dest_root="${HOME}/Applications"
    mkdir -p "$dest_root"
    log "no write access to /Applications — installing to $dest_root"
  fi
  local app_dest="${dest_root}/Bleep.app"

  # remove previous install to avoid hybrid trees (idempotent)
  rm -rf "$app_dest"
  tar -xzf "${TMP}/${archive}" -C "$dest_root"

  # Gatekeeper clearance — must run BEFORE first launch to prevent App Translocation
  xattr -r -d com.apple.quarantine "$app_dest" 2>/dev/null || true

  # ad-hoc codesign — mandatory on Apple Silicon, harmless on Intel
  if have codesign; then
    codesign --force --deep -s - "$app_dest" 2>/dev/null \
      || log "warning: codesign failed — app may still work on Intel but not Apple Silicon"
  else
    log "warning: codesign not found (install Xcode CLT). App may not launch on Apple Silicon."
  fi

  printf '%s' "$app_dest"
}

install_launch_agent() {
  local plist="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}"
  local gw="${PREFIX}/bin/bleep-gateway"
  mkdir -p "${HOME}/Library/LaunchAgents"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${gw}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>StandardOutPath</key><string>/tmp/bleep-gateway.out.log</string>
  <key>StandardErrorPath</key><string>/tmp/bleep-gateway.err.log</string>
</dict>
</plist>
PLIST
  # unload if already loaded (idempotent)
  launchctl bootout "gui/$(id -u)" "$plist" 2>/dev/null || true
  if launchctl bootstrap "gui/$(id -u)" "$plist"; then
    log "LaunchAgent installed and started: ${LAUNCH_AGENT_LABEL}"
  else
    log "warning: launchctl bootstrap failed — plist is at $plist (you can load manually)"
  fi
}

install_claude_override() {
  # resolve the real claude binary: follow symlinks so we store the actual
  # executable, not a chain that might later point back to our shim.
  local claude_on_path real_claude
  claude_on_path="$(command -v claude 2>/dev/null || true)"
  if [ -z "$claude_on_path" ]; then
    log "warning: 'claude' not found on PATH — skipping claude override"
    return
  fi
  real_claude="$(readlink -f "$claude_on_path" 2>/dev/null || realpath "$claude_on_path" 2>/dev/null || echo "$claude_on_path")"
  # if the resolved path already is our wrapper, nothing to do
  if [ "$real_claude" = "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh" ]; then
    log "claude override already in place"
    return
  fi

  # store the real path so the wrapper can bypass the shim on future launches
  printf '%s' "$real_claude" > "${PREFIX}/${INSTALL_LIB_REL}/.claude-path"
  chmod 0644 "${PREFIX}/${INSTALL_LIB_REL}/.claude-path"

  # ad-hoc re-sign — claude auto-updates frequently ship unsigned binaries
  if have codesign; then
    log "signing $real_claude"
    codesign --force -s - "$real_claude" 2>/dev/null \
      || log "warning: codesign failed — claude may be killed by macOS on launch"
  fi

  # create claude shim pointing to the bleep wrapper
  ln -sf "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh" "${PREFIX}/bin/claude"
  log "claude override installed: ${PREFIX}/bin/claude -> bleep-wrapper.sh (real binary: $real_claude)"
}

uninstall() {
  log "uninstalling Bleep..."

  # 1. unload + remove LaunchAgent if present
  local plist="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}"
  if [ -f "$plist" ]; then
    launchctl bootout "gui/$(id -u)" "$plist" 2>/dev/null || true
    rm -f "$plist"
    log "removed LaunchAgent: $plist"
  fi

  # 2. remove symlinks + gateway binary (claude shim only if it points to us)
  rm -f "${PREFIX}/bin/bleep" "${PREFIX}/bin/bleep-gateway"
  local claude_link="${PREFIX}/bin/claude"
  if [ -L "$claude_link" ] && \
     [ "$(readlink "$claude_link")" = "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh" ]; then
    rm -f "$claude_link"
    log "removed claude override: $claude_link"
  fi
  log "removed binaries from ${PREFIX}/bin"

  # 3. remove install lib tree (wrapper, cert.pem, .version)
  rm -rf "${PREFIX}/${INSTALL_LIB_REL}"
  log "removed lib tree: ${PREFIX}/${INSTALL_LIB_REL}"

  # 4. remove app bundle from whichever Applications dir holds it
  for cand in "/Applications/Bleep.app" "${HOME}/Applications/Bleep.app"; do
    if [ -d "$cand" ]; then
      rm -rf "$cand"
      log "removed $cand"
    fi
  done

  # 5. intentionally preserve user data: ~/Library/Application Support/bleep
  log "uninstall complete (user data in ~/Library/Application Support/bleep preserved)"
}

print_summary() {
  local app_path="${1:-unknown}"
  local la_status="${2:-skipped}"
  local claude_status="${3:-skipped}"
  cat >&2 <<SUMMARY

  Bleep ${VERSION} installed successfully!

  Installed files:
    gateway binary : ${PREFIX}/bin/bleep-gateway
    bleep command  : ${PREFIX}/bin/bleep  (symlink)
    wrapper script : ${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh
    CA cert        : ${PREFIX}/${INSTALL_LIB_REL}/src/cert.pem
    claude override: ${claude_status}
    app bundle     : ${app_path}
    LaunchAgent    : ${la_status}

SUMMARY

  # PATH hint when $PREFIX/bin is not on PATH
  case ":${PATH}:" in
    *":${PREFIX}/bin:"*) ;;
    *)
      cat >&2 <<PATH_HINT
  NOTE: ${PREFIX}/bin is not in your PATH.
  Add this to your shell profile (~/.zshrc or ~/.bash_profile):
    export PATH="${PREFIX}/bin:\$PATH"
  Then restart your terminal or run: source ~/.zshrc

PATH_HINT
      ;;
  esac
}

# ============================================================
# Local build (--local mode)
# ============================================================

build_local_artifacts() {
  [ -f "Cargo.toml" ]              || die "--local must be run from the repo root (Cargo.toml not found)"
  [ -d "apps/menu-bar/src-tauri" ] || die "--local requires apps/menu-bar/src-tauri/ in the repo"
  have cargo                       || die "--local requires cargo (install Rust via rustup)"

  log "building bleep-gateway (release)..."
  cargo build --release --bin bleep-gateway

  log "building Bleep.app (release) for ${TARGET}..."
  (cd apps/menu-bar/src-tauri && cargo tauri build --target "${TARGET}")
}

install_gateway_local() {
  mkdir -p "${PREFIX}/bin" "${PREFIX}/${INSTALL_LIB_REL}/src"
  if [ -e "${PREFIX}/bin/bleep" ] && [ ! -L "${PREFIX}/bin/bleep" ]; then
    rm -f "${PREFIX}/bin/bleep"
  fi
  cp "target/release/bleep-gateway"  "${PREFIX}/bin/bleep-gateway"
  cp "claude-wrapper.sh"             "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh"
  bash "scripts/extract-cert.sh"     "${PREFIX}/${INSTALL_LIB_REL}/src"
  echo "local"                      > "${PREFIX}/${INSTALL_LIB_REL}/.version"
  chmod 0755 "${PREFIX}/bin/bleep-gateway" "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh"
  chmod 0644 "${PREFIX}/${INSTALL_LIB_REL}/src/cert.pem"
  ln -sf "${PREFIX}/${INSTALL_LIB_REL}/bleep-wrapper.sh" "${PREFIX}/bin/bleep"
  log "installed bleep-gateway and wrapper"
}

install_app_bundle_local() {
  local src_app="apps/menu-bar/src-tauri/target/${TARGET}/release/bundle/macos/Bleep.app"
  [ -d "$src_app" ] || die "Bleep.app not found at $src_app"
  local dest_root="/Applications"
  if [ ! -w "$dest_root" ]; then
    dest_root="${HOME}/Applications"
    mkdir -p "$dest_root"
    log "no write access to /Applications — installing to $dest_root"
  fi
  local app_dest="${dest_root}/Bleep.app"
  rm -rf "$app_dest"
  cp -R "$src_app" "$app_dest"
  xattr -r -d com.apple.quarantine "$app_dest" 2>/dev/null || true
  if have codesign; then
    codesign --force --deep -s - "$app_dest" 2>/dev/null \
      || log "warning: codesign failed — app may not launch on Apple Silicon"
  fi
  printf '%s' "$app_dest"
}

# ============================================================
# Main
# ============================================================

main() {
  # short-circuit for uninstall — no network calls needed
  if [ "$DO_UNINSTALL" = "1" ]; then
    uninstall
    exit 0
  fi

  local TARGET VERSION TMP="" APP_PATH LA_STATUS="skipped" CLAUDE_STATUS="skipped"
  trap 'rm -rf "${TMP:-}"' EXIT

  TARGET=$(detect_target)
  log "detected target: ${TARGET}"

  # ── local build path ──────────────────────────────────────
  if [ "$DO_LOCAL" = "1" ]; then
    VERSION="local"
    build_local_artifacts
    install_gateway_local
    APP_PATH=$(install_app_bundle_local)
    if [ "$OVERRIDE_CLAUDE" = "1" ]; then
      install_claude_override
      CLAUDE_STATUS="${PREFIX}/bin/claude (shim)"
    fi
    case "$LAUNCH_AGENT_CHOICE" in
      yes) install_launch_agent; LA_STATUS="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}" ;;
      no)  log "skipping LaunchAgent" ;;
      ask)
        if [ -t 0 ]; then
          read -r -p "[bleep] install LaunchAgent for gateway auto-start on login? [y/N] " ans
          case "$ans" in
            [yY]|[yY][eE][sS]) install_launch_agent; LA_STATUS="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}" ;;
            *) log "skipping LaunchAgent" ;;
          esac
        else
          log "non-interactive — skipping LaunchAgent"
        fi
        ;;
    esac
    print_summary "$APP_PATH" "$LA_STATUS" "$CLAUDE_STATUS"
    return
  fi

  VERSION=$(resolve_version)
  log "installing version: ${VERSION}"

  # re-run detection — emit upgrade notice if already installed
  if [ -f "${PREFIX}/${INSTALL_LIB_REL}/.version" ]; then
    local prev
    prev=$(cat "${PREFIX}/${INSTALL_LIB_REL}/.version" 2>/dev/null || echo unknown)
    log "existing install detected (version ${prev}) — upgrading to ${VERSION}"
  fi

  TMP=$(mktemp -d)
  mkdir -p "${TMP}/extract"

  local BASE_URL
  if [ -n "${BLEEP_RELEASE_BASE:-}" ]; then
    BASE_URL="$BLEEP_RELEASE_BASE"
    log "using BLEEP_RELEASE_BASE override: $BASE_URL"
  else
    BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}"
  fi

  # download checksums first, then archives
  log "downloading checksums.txt"
  curl -fsSL --retry 3 "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"

  download_and_verify "bleep-gateway-${TARGET}.tar.gz"   "${BASE_URL}"
  download_and_verify "Bleep.app-${TARGET}.tar.gz"       "${BASE_URL}"

  install_gateway_archive
  APP_PATH=$(install_app_bundle)
  if [ "$OVERRIDE_CLAUDE" = "1" ]; then
    install_claude_override
    CLAUDE_STATUS="${PREFIX}/bin/claude (shim)"
  fi

  # LaunchAgent dispatch
  case "$LAUNCH_AGENT_CHOICE" in
    yes)
      install_launch_agent
      LA_STATUS="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}"
      ;;
    no)
      log "skipping LaunchAgent (gateway will not auto-start on login)"
      ;;
    ask)
      if [ -t 0 ]; then
        read -r -p "[bleep] install LaunchAgent for gateway auto-start on login? [y/N] " ans
        case "$ans" in
          [yY]|[yY][eE][sS])
            install_launch_agent
            LA_STATUS="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_PLIST_NAME}"
            ;;
          *)
            log "skipping LaunchAgent"
            ;;
        esac
      else
        log "non-interactive (piped) — skipping LaunchAgent. Re-run with --launch-agent to install."
      fi
      ;;
  esac

  print_summary "$APP_PATH" "$LA_STATUS" "$CLAUDE_STATUS"
}

main "$@"
