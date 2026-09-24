#!/usr/bin/env python3
"""Allocate and touch RAM to create memory pressure anomaly."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.simulate.loads import pressure_memory


def main() -> int:
    p = argparse.ArgumentParser(description="Memory pressure for anomaly simulation")
    p.add_argument("--duration", type=float, default=300.0)
    p.add_argument("--mb", type=int, default=512, help="megabytes to allocate")
    args = p.parse_args()
    print(f"mem pressure duration={args.duration}s mb={args.mb}")
    pressure_memory(args.duration, megabytes=args.mb)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
