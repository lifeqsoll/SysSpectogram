#!/usr/bin/env bash
# Smoke-validate a profile pack: quiet window should score below threshold-ish;
# synthetic burn should score higher. Not a full FP study.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PACK="${1:?usage: validate-pack.sh path/to/profile-*.tar.gz [sha256]}"
SHA="${2:-}"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ARGS=(--insecure)
if [[ -n "$SHA" ]]; then
  ARGS=(--sha256 "$SHA")
fi
python -m sysspectogram profiles install "$PACK" --dest "$TMP/prof" "${ARGS[@]}"
HOST=$(find "$TMP/prof" -type d -name host | head -1)
[[ -n "$HOST" ]] || { echo "no host/ in pack"; exit 1; }

python - <<PY
from pathlib import Path
import numpy as np
from sysspectogram.ml.infer import load_inferencer

host = Path("$HOST")
infer = load_inferencer(host)
cols = len(getattr(infer, "columns", None) or getattr(infer, "feature_columns", []) or [0]*32)
ws = int(getattr(infer, "window_size", 60))
# quiet-ish synthetic window
w = np.random.default_rng(0).normal(loc=5.0, scale=1.0, size=(ws, cols)).astype(np.float32)
w = np.clip(w, 0, 20)
pred_q = infer.predict_window(w)
h = np.random.default_rng(1).normal(loc=70.0, scale=10.0, size=(ws, cols)).astype(np.float32)
pred_h = infer.predict_window(h)
print(f"quiet score={pred_q.score:.3f} thr={pred_q.threshold:.3f} anom={pred_q.is_anomaly}")
print(f"hot   score={pred_h.score:.3f} thr={pred_h.threshold:.3f} anom={pred_h.is_anomaly}")
if pred_h.score <= pred_q.score:
    raise SystemExit("pack smoke failed: hot score not above quiet")
print("pack smoke OK")
PY
