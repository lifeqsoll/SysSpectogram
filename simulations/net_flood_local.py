#!/usr/bin/env python3
"""Localhost TCP connection flood (no external network scan)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sysspectogram.simulate.loads import flood_local_net


def main() -> int:
    p = argparse.ArgumentParser(description="Local TCP flood for anomaly simulation")
    p.add_argument("--duration", type=float, default=900.0)
    p.add_argument("--rate", type=int, default=80, help="connections per second")
    args = p.parse_args()
    print(f"net flood local duration={args.duration}s rate={args.rate}/s")
    flood_local_net(args.duration, connections_per_sec=args.rate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
