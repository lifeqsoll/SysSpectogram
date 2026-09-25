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

echo "==> SysSpectogram bootstrap tag=$TAG prefix=$PREFIX"

if [[ ! -d "$PREFIX/.git" ]]; then
  sudo mkdir -p "$(dirname "$PREFIX")"
  sudo git clone --depth 1 --branch "$TAG" "$REPO_URL" "$PREFIX" \
    || sudo git clone --depth 1 "$REPO_URL" "$PREFIX"
fi

cd "$PREFIX"
export PREFIX LOAD_PROFILE INSTALL_ML INSTALL_ONNX
sudo -E bash scripts/install.sh

echo ""
echo "Next:"
echo "  1) sudo cp $PREFIX/.env.example $PREFIX/.env  # fill TELEGRAM_*"
echo "  2) python -m sysspectogram setup --prefix $PREFIX   # if available"
echo "  3) sudo systemctl enable --now sysspectogram-guard.service"
echo "  4) Read unlock code on console → TG /unlock CODE"
echo ""
echo "Pull role pack (optional):"
echo "  source $PREFIX/.venv/bin/activate"
echo "  python -m sysspectogram profiles pull --url <release-url> --out /tmp/p.tar.gz --sha256 <hex>"
