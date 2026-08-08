#!/usr/bin/env bash
# Install Mjölnir as a systemd --user service on your local Linux machine.
#
# What you get:
#   - mjolnir-update.service  → git pull + rebuild on login
#   - mjolnir-server.service  → starts the API after update
#
# Usage (from a clone of this repo):
#   ./scripts/install-linux-service.sh
#   ./scripts/install-linux-service.sh --no-auto-update
set -euo pipefail

AUTO_UPDATE=1
for arg in "$@"; do
  case "$arg" in
    --no-auto-update) AUTO_UPDATE=0 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_URL="${MJOLNIR_REPO_URL:-https://github.com/nulli83/Mj-lnir.git}"
BRANCH="${MJOLNIR_BRANCH:-main}"

SHARE_DIR="$HOME/.local/share/mjolnir"
BIN_DIR="$SHARE_DIR/bin"
SRC_DIR="$SHARE_DIR/src"
DATA_DIR="$SHARE_DIR/data"
CONFIG_DIR="$HOME/.config/mjolnir"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

mkdir -p "$BIN_DIR" "$DATA_DIR" "$CONFIG_DIR" "$SYSTEMD_USER_DIR" "$SHARE_DIR/logs"

echo "[*] Installing helper scripts"
install -m 755 "$REPO_ROOT/scripts/mjolnir-update.sh" "$BIN_DIR/mjolnir-update.sh"

echo "[*] Ensuring managed clone at $SRC_DIR"
if [[ -L "$SRC_DIR" ]]; then
  rm -f "$SRC_DIR"
fi

if [[ ! -d "$SRC_DIR/.git" ]]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
else
  git -C "$SRC_DIR" remote set-url origin "$REPO_URL"
  git -C "$SRC_DIR" fetch --prune origin "$BRANCH"
  git -C "$SRC_DIR" checkout "$BRANCH"
  git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
fi

if [[ ! -f "$CONFIG_DIR/server.env" ]]; then
  echo "[*] Creating $CONFIG_DIR/server.env"
  sed "s|/home/REPLACE_ME|$HOME|g" \
    "$REPO_ROOT/server/systemd/server.env.example" > "$CONFIG_DIR/server.env"
  chmod 600 "$CONFIG_DIR/server.env"
  echo "    Edit secrets there before production use."
else
  echo "[*] Keeping existing $CONFIG_DIR/server.env"
fi

echo "[*] Installing systemd user units"
install -m 644 "$REPO_ROOT/server/systemd/mjolnir-server.service" \
  "$SYSTEMD_USER_DIR/mjolnir-server.service"
install -m 644 "$REPO_ROOT/server/systemd/mjolnir-update.service" \
  "$SYSTEMD_USER_DIR/mjolnir-update.service"

echo "[*] First build + install binary"
MJOLNIR_REPO_URL="$REPO_URL" \
MJOLNIR_REPO_DIR="$SRC_DIR" \
MJOLNIR_BRANCH="$BRANCH" \
MJOLNIR_BIN_DIR="$BIN_DIR" \
MJOLNIR_DATA_DIR="$DATA_DIR" \
  "$BIN_DIR/mjolnir-update.sh"

echo "[*] Enabling lingering so user services can run after logout"
if command -v loginctl >/dev/null 2>&1; then
  loginctl enable-linger "$USER" >/dev/null 2>&1 || true
fi

systemctl --user daemon-reload

if [[ "$AUTO_UPDATE" -eq 1 ]]; then
  systemctl --user enable mjolnir-update.service
  systemctl --user enable mjolnir-server.service
  systemctl --user start mjolnir-update.service
  systemctl --user restart mjolnir-server.service
  echo "[+] Auto-update on login: ON"
else
  systemctl --user disable mjolnir-update.service 2>/dev/null || true
  systemctl --user enable --now mjolnir-server.service
  echo "[+] Auto-update on login: OFF (server still starts on login)"
fi

echo
echo "Done. On this machine:"
echo "  Health:  curl http://127.0.0.1:8787/health"
echo "  Status:  systemctl --user status mjolnir-server.service"
echo "  Logs:    journalctl --user -u mjolnir-server.service -f"
echo "  Config:  $CONFIG_DIR/server.env"
echo "  Manual:  $BIN_DIR/mjolnir-update.sh"
echo
echo "Disable:"
echo "  systemctl --user disable --now mjolnir-server.service mjolnir-update.service"
