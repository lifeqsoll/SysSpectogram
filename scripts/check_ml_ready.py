#!/usr/bin/env python3
"""Exit 0 only if offline fuse eval beats zscore (safe enablement gate).

Does **not** change configs/default.yaml. Friend path stays notorch until you
explicitly set runtime.prefer after this passes.

Usage:
  python scripts/check_ml_ready.py --dataset dataset/raw_v4 --model artifacts/raw_v4
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--runtime", default="onnx")
    ap.add_argument("--out", type=Path, default=Path("reports/eval/gate"))
    args = ap.parse_args()
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "eval_offline.py"),
        "--dataset",
        str(args.dataset),
        "--model",
        str(args.model),
        "--methods",
        "fuse,cnn,iforest,zscore",
        "--runtime",
        args.runtime,
        "--out",
        str(args.out),
        "--gate",
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
