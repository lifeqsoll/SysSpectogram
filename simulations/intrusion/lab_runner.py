#!/usr/bin/env python3
"""Lab wrapper: only runs when --lab is set. Documents dangerous scenarios."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    p = argparse.ArgumentParser(description="Intrusion lab runner (explicit --lab required)")
    p.add_argument("--lab", action="store_true", required=True)
    p.add_argument(
        "scenario",
        choices=["ssh_bruteforce", "port_scan_local", "egress_beacon", "egress_local"],
    )
    p.add_argument("--duration", type=float, default=8.0)
    args, rest = p.parse_known_args()
    if args.scenario == "ssh_bruteforce":
        cmd = [sys.executable, str(HERE / "ssh_bruteforce_local.py"), *rest]
    elif args.scenario == "port_scan_local":
        cmd = [sys.executable, str(HERE / "port_scan_local.py"), *rest]
    elif args.scenario == "egress_beacon":
        cmd = [
            sys.executable,
            str(HERE / "egress_beacon.py"),
            "--lab",
            "--duration",
            str(args.duration),
            *rest,
        ]
    else:
        cmd = [
            sys.executable,
            str(HERE / "egress_beacon.py"),
            "--local-sink",
            "--duration",
            str(args.duration),
            *rest,
        ]
    print("lab:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
