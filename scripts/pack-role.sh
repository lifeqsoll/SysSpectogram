#!/usr/bin/env bash
# Collect + train + pack one role (builder PC).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROLE="${1:?usage: pack-role.sh <role> [duration_sec]}"
DUR="${2:-600}"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

OUT_DIR="artifacts/rolelab/${ROLE}"
ART="artifacts/profiles/${ROLE}/host"
PACK="dist/profile-${ROLE}-v1.tar.gz"

python -m sysspectogram role-lab run --role "$ROLE" --out "$OUT_DIR" --duration "$DUR" --synthetic-only
python -m sysspectogram role-lab train --role-dir "$OUT_DIR" --out "$ART" --pack "$PACK"
echo "pack ready: $PACK"
cat "${PACK}.sha256" 2>/dev/null || sha256sum "$PACK"
