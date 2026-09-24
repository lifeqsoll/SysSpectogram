#!/usr/bin/env bash
# Orchestrate anomaly simulations. Run collect in another terminal while this runs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DURATION_CPU="${DURATION_CPU:-600}"
DURATION_NET="${DURATION_NET:-600}"
DURATION_MEM="${DURATION_MEM:-180}"
DURATION_DISK="${DURATION_DISK:-180}"

echo "Running anomaly scenarios under $ROOT/simulations"
python "$ROOT/simulations/cpu_miner.py" --duration "$DURATION_CPU" &
PID_CPU=$!
python "$ROOT/simulations/net_flood_local.py" --duration "$DURATION_NET" &
PID_NET=$!
python "$ROOT/simulations/mem_pressure.py" --duration "$DURATION_MEM" --mb 256 &
PID_MEM=$!
python "$ROOT/simulations/disk_thrash.py" --duration "$DURATION_DISK" &
PID_DISK=$!

wait "$PID_CPU" "$PID_NET" "$PID_MEM" "$PID_DISK"
echo "done"
