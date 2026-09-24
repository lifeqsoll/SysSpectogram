#!/usr/bin/env python3
"""Simulate sustained high CPU load (miner-like). Safe: burns local CPU only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.simulate.loads import burn_cpu


def main() -> int:
    p = argparse.ArgumentParser(description="CPU miner-like load for dataset labeling")
    p.add_argument("--duration", type=float, default=900.0, help="seconds")
    p.add_argument("--workers", type=int, default=None, help="worker processes")
    args = p.parse_args()
    print(f"cpu burn duration={args.duration}s workers={args.workers or 'auto'}")
    burn_cpu(args.duration, workers=args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
