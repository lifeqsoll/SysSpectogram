#!/usr/bin/env bash
# One-shot VPS bootstrap (no Torch by default).
set -euo pipefail
REPO_URL="${REPO_URL:-https://github.com/lifeqsoll/SysSpectogram.git}"
TAG="${TAG:-v0.5.0}"
PREFIX="${PREFIX:-/opt/sysspectogram}"
LOAD_PROFILE="${LOAD_PROFILE:-lite}"
INSTALL_ML="${INSTALL_ML:-0}"
INSTALL_ONNX="${INSTALL_ONNX:-1}"
ROLE="${ROLE:-generic-linux}"

echo "==> SysSpectogram bootstrap tag=$TAG prefix=$PREFIX role=$ROLE"

if [[ ! -d "$PREFIX/.git" ]]; then
  sudo mkdir -p "$(dirname "$PREFIX")"
  sudo git clone --depth 1 --branch "$TAG" "$REPO_URL" "$PREFIX" \
    || sudo git clone --depth 1 "$REPO_URL" "$PREFIX"
fi

cd "$PREFIX"
export PREFIX LOAD_PROFILE INSTALL_ML INSTALL_ONNX
sudo -E bash scripts/install.sh

UNITS_SRC="$PREFIX/packaging"
if [[ -d "$PREFIX/scripts/systemd" ]]; then
  UNITS_SRC="$PREFIX/scripts/systemd"
fi
if [[ -f "$UNITS_SRC/sysspectogram-agent.service" ]]; then
  echo "==> install agent unit from $UNITS_SRC"
  sudo cp "$UNITS_SRC"/sysspectogram-*.service /etc/systemd/system/ 2>/dev/null || true
  sudo systemctl daemon-reload || true
fi

echo ""
echo "Next:"
echo "  1) sudo cp $PREFIX/.env.example $PREFIX/.env  # fill TELEGRAM_*"
echo "  2) source $PREFIX/.venv/bin/activate"
echo "  3) python -m sysspectogram setup --prefix $PREFIX --role $ROLE"
echo "  4) sudo systemctl enable --now sysspectogram-guard.service"
echo "  5) Read unlock code on console; TG /unlock CODE"
echo "  6) Guard writes state/agent_hmac.secret - agent must use the same file"
echo ""
echo "Pull role pack (optional, verify sha256):"
echo "  python -m sysspectogram profiles pull --url <release-url> --out /tmp/p.tar.gz --sha256 <hex>"
echo "  python -m sysspectogram profiles install /tmp/p.tar.gz --dest artifacts/profiles/\$ROLE --sha256 <hex>"
echo "  bash scripts/validate-pack.sh /tmp/p.tar.gz <hex>"
