#!/usr/bin/env python3
"""Exit 0 only if fuse beats the best statistical baseline (Phase 7.4 gate).

Does **not** change configs/default.yaml. Friend path stays notorch / experimental
until this passes on an honest (raw schema v2) dataset.

Usage:
  python scripts/check_ml_ready.py --dataset dataset/raw_v4 --model artifacts/raw_v4
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def gate_from_metrics(metrics: dict) -> tuple[int, str]:
    """Pure gate used by tests — same rule as eval_offline --gate."""
    fuse = (metrics.get("methods") or {}).get("fuse")
    baselines = metrics.get("baselines") or {
        k: v
        for k, v in (metrics.get("methods") or {}).items()
        if k in {"zscore", "robust_z", "ewma", "iforest_stats", "pca"}
    }
    if not fuse:
        return 1, "need fuse method"
    if not baselines:
        return 1, "need baselines"
    best_name = metrics.get("best_baseline")
    best = baselines.get(best_name) if best_name else None
    if best is None:
        best_name, best = max(
            baselines.items(),
            key=lambda kv: (kv[1].get("pr_auc") is not None, kv[1].get("pr_auc") or -1.0),
        )
    fuse_pr, best_pr = fuse.get("pr_auc"), best.get("pr_auc")
    fuse_r1, best_r1 = fuse.get("recall_at_fpr_1pct"), best.get("recall_at_fpr_1pct")
    if fuse_pr is None or best_pr is None:
        return 1, "missing PR-AUC"
    if float(fuse_pr) <= float(best_pr):
        return 1, f"fuse PR-AUC {fuse_pr} <= baseline {best_name} {best_pr}"
    if fuse_r1 is None or best_r1 is None or float(fuse_r1) < float(best_r1):
        return 1, f"fuse recall@FPR1% {fuse_r1} < baseline {best_name} {best_r1}"
    if metrics.get("warnings"):
        return 1, "warnings present"
    return 0, f"ok vs {best_name}"


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--runtime", default="onnx")
    ap.add_argument("--out", type=Path, default=Path("reports/eval/gate"))
    ap.add_argument(
        "--metrics-json",
        type=Path,
        default=None,
        help="skip eval; gate an existing metrics.json (for tests / CI)",
    )
    args = ap.parse_args()

    if args.metrics_json is not None:
        data = json.loads(Path(args.metrics_json).read_text(encoding="utf-8"))
        code, msg = gate_from_metrics(data)
        print(msg, file=sys.stderr)
        return code

    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "eval_offline.py"),
        "--dataset",
        str(args.dataset),
        "--model",
        str(args.model),
        "--methods",
        "fuse,cnn,iforest,zscore,robust_z,ewma,iforest_stats,pca",
        "--runtime",
        args.runtime,
        "--out",
        str(args.out),
        "--gate",
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
