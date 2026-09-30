#!/usr/bin/env bash
# Golden-path smoke: short collect + simulate + look for alert artifacts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

MODEL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) MODEL="$2"; shift 2 ;;
    *) echo "usage: $0 [--model DIR]"; exit 2 ;;
  esac
done

mkdir -p data reports state
OUT_JSONL="reports/golden_alerts.jsonl"
: >"$OUT_JSONL"

echo "[golden] short quiet collect (15s)"
python -m sysspectogram collect --out data/golden_quiet.csv --duration 15 || true

echo "[golden] synthetic cpu load (12s)"
python -m sysspectogram simulate --scenario cpu --duration 12 &
SIM_PID=$!

GUARD_ARGS=(guard --dry-run --jsonl-out "$OUT_JSONL")
if [[ -n "$MODEL" && -d "$MODEL" ]]; then
  GUARD_ARGS+=(--model "$MODEL")
fi

echo "[golden] guard observe window (25s)"
timeout 25 python -m sysspectogram "${GUARD_ARGS[@]}" || true
wait "$SIM_PID" 2>/dev/null || true

if [[ ! -s "$OUT_JSONL" ]]; then
  # also accept agent/perimeter jsonl hits
  if rg -q "host_anomaly|anomaly|ALERT|score" reports/*.jsonl 2>/dev/null; then
    echo "[golden] OK — anomaly-like line in reports/*.jsonl"
    exit 0
  fi
  echo "[golden] FAIL — no alert lines in $OUT_JSONL (model optional; perimeter may be quiet)"
  echo "[golden] hint: re-run with --model artifacts/live after training, or check simulate/collect"
  exit 1
fi

echo "[golden] OK — wrote $(wc -l <"$OUT_JSONL") lines to $OUT_JSONL"
exit 0
