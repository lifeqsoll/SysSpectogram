#!/usr/bin/env bash
# Minimal install helper for VPS/VDS. Run from repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/opt/sysspectogram}"
LOAD_PROFILE="${LOAD_PROFILE:-lite}"  # lite|full

echo "==> install prefix: $PREFIX  load_profile=$LOAD_PROFILE"
sudo mkdir -p "$PREFIX"/{artifacts,state,reports,agent}
sudo rsync -a --exclude .venv --exclude agent/target --exclude .git "$ROOT"/ "$PREFIX"/

if [[ ! -d "$PREFIX/.venv" ]]; then
  sudo python3 -m venv "$PREFIX/.venv"
fi
# shellcheck disable=SC1091
source "$PREFIX/.venv/bin/activate"
pip install -U pip
pip install "torch" --index-url https://download.pytorch.org/whl/cpu || true
pip install -e "$PREFIX/[dev]"

if command -v cargo >/dev/null 2>&1; then
  (cd "$PREFIX/agent" && cargo build --release)
else
  echo "WARN: cargo not found — skip agent binary"
fi

# Persist load profile
if [[ -f "$PREFIX/configs/default.yaml" ]]; then
  sudo sed -i "s/^load_profile:.*/load_profile: ${LOAD_PROFILE}/" "$PREFIX/configs/default.yaml" || true
fi

echo "==> units (optional):"
echo "  sudo cp $PREFIX/scripts/systemd/*.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now sysspectogram-guard.service"
echo "Done. Put secrets in $PREFIX/.env"
