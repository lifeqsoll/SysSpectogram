#!/usr/bin/env python3
"""Aggressive local disk read/write thrash."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.simulate.loads import thrash_disk


def main() -> int:
    p = argparse.ArgumentParser(description="Disk thrash anomaly simulation")
    p.add_argument("--duration", type=float, default=300.0)
    p.add_argument("--block-mb", type=int, default=32)
    p.add_argument("--path", type=Path, default=Path("/tmp/sysspectogram_disk_thrash.bin"))
    args = p.parse_args()
    print(f"disk thrash duration={args.duration}s path={args.path}")
    thrash_disk(args.duration, path=args.path, block_mb=args.block_mb)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
