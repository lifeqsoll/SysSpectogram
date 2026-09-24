#!/usr/bin/env python3
"""Light GPU burn for labeling (CUDA only). Safe: local GPU compute."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.simulate.loads import burn_gpu


def main() -> int:
    p = argparse.ArgumentParser(description="Light CUDA GPU burn")
    p.add_argument("--duration", type=float, default=120.0)
    p.add_argument("--size", type=int, default=2048, help="matmul matrix size")
    args = p.parse_args()
    print(f"gpu burn duration={args.duration}s size={args.size}")
    burn_gpu(args.duration, size=args.size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
