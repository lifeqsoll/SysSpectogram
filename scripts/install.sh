#!/usr/bin/env bash
# Minimal install helper for VPS/VDS. Run from repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/opt/sysspectogram}"
LOAD_PROFILE="${LOAD_PROFILE:-lite}"  # lite|full
INSTALL_ML="${INSTALL_ML:-0}"         # 1 = also install torch (builder)
INSTALL_ONNX="${INSTALL_ONNX:-1}"     # 1 = onnxruntime for cnn.onnx infer

echo "==> install prefix: $PREFIX  load_profile=$LOAD_PROFILE INSTALL_ML=$INSTALL_ML INSTALL_ONNX=$INSTALL_ONNX"
sudo mkdir -p "$PREFIX"/{artifacts,state,reports,agent}
sudo rsync -a --exclude .venv --exclude agent/target --exclude .git "$ROOT"/ "$PREFIX"/

if [[ ! -d "$PREFIX/.venv" ]]; then
  sudo python3 -m venv "$PREFIX/.venv"
fi
# shellcheck disable=SC1091
source "$PREFIX/.venv/bin/activate"
pip install -U pip
EXTRAS="dev"
if [[ "$INSTALL_ONNX" == "1" ]]; then
  EXTRAS="${EXTRAS},onnx"
fi
if [[ "$INSTALL_ML" == "1" ]]; then
  pip install "torch" --index-url https://download.pytorch.org/whl/cpu || true
  EXTRAS="${EXTRAS},ml"
fi
pip install -e "${PREFIX}[${EXTRAS}]"

if command -v cargo >/dev/null 2>&1; then
  (cd "$PREFIX/agent" && cargo build --release)
else
  echo "WARN: cargo not found — skip agent binary"
fi

# Persist load profile + default runtime
if [[ -f "$PREFIX/configs/default.yaml" ]]; then
  sudo sed -i "s/^load_profile:.*/load_profile: ${LOAD_PROFILE}/" "$PREFIX/configs/default.yaml" || true
  if [[ "$INSTALL_ML" != "1" ]]; then
    if [[ "$INSTALL_ONNX" == "1" ]]; then
      sudo sed -i "s/^runtime:.*/runtime: onnx/" "$PREFIX/configs/default.yaml" || true
    else
      sudo sed -i "s/^runtime:.*/runtime: notorch/" "$PREFIX/configs/default.yaml" || true
    fi
  fi
fi

echo "==> units (optional):"
echo "  sudo cp $PREFIX/scripts/systemd/*.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now sysspectogram-guard.service"
echo "Done. Put secrets in $PREFIX/.env"
echo "VPS tip: keep INSTALL_ML=0; use export-onnx on a builder then ship cnn.onnx"
