#!/usr/bin/env bash
# Pull latest Mjölnir, rebuild the self-hosted server, restart the user service.
set -euo pipefail

REPO_URL="${MJOLNIR_REPO_URL:-https://github.com/nulli83/Mj-lnir.git}"
REPO_DIR="${MJOLNIR_REPO_DIR:-$HOME/.local/share/mjolnir/src}"
BRANCH="${MJOLNIR_BRANCH:-main}"
BIN_DIR="${MJOLNIR_BIN_DIR:-$HOME/.local/share/mjolnir/bin}"
DATA_DIR="${MJOLNIR_DATA_DIR:-$HOME/.local/share/mjolnir/data}"
LOG_DIR="${MJOLNIR_LOG_DIR:-$HOME/.local/share/mjolnir/logs}"

mkdir -p "$BIN_DIR" "$DATA_DIR" "$LOG_DIR"

log() {
  echo "[mjolnir-update $(date -Iseconds)] $*" | tee -a "$LOG_DIR/update.log"
}

if ! command -v git >/dev/null 2>&1; then
  log "ERROR: git is required"
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  log "ERROR: cargo/rust is required (install via rustup)"
  exit 1
fi

if [[ ! -d "$REPO_DIR/.git" ]]; then
  log "Cloning $REPO_URL into $REPO_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
else
  log "Fetching $BRANCH in $REPO_DIR"
  git -C "$REPO_DIR" fetch --prune origin "$BRANCH"
  git -C "$REPO_DIR" checkout "$BRANCH"
  git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
fi

log "Building mjolnir_server (release)"
cargo build --release --manifest-path "$REPO_DIR/server/Cargo.toml"

install -m 755 "$REPO_DIR/server/target/release/mjolnir_server" "$BIN_DIR/mjolnir_server"
install -m 755 "$REPO_DIR/scripts/mjolnir-update.sh" "$BIN_DIR/mjolnir-update.sh"

if systemctl --user --quiet is-enabled mjolnir-server.service 2>/dev/null \
  || systemctl --user --quiet is-active mjolnir-server.service 2>/dev/null; then
  log "Restarting mjolnir-server.service"
  systemctl --user restart mjolnir-server.service || true
fi

log "Update complete → $BIN_DIR/mjolnir_server"
