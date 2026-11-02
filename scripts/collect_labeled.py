#!/usr/bin/env python3
"""Scaffold: schedule MetricsCollector + simulation scenarios → labels.csv.

Full multi-host 3-day campaigns are operator-run. This script writes a
labels.csv aligned to scenario windows for short dry-runs / CI fixtures.
"""

from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path


SCENARIOS = [
    "miner_low",
    "miner_high",
    "ssh_bruteforce",
    "reverse_shell_local",
    "exfil_local",
    "fork_bomb_cgroup",
    "legit_compress",
    "legit_build",
    "legit_download",
    "legit_backup",
]


def write_labels(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["start", "end", "scenario", "label"])
        w.writeheader()
        for row in rows:
            w.writerow(row)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("data/labels.csv"))
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="write a synthetic schedule without launching collectors",
    )
    ap.add_argument("--base-ts", type=float, default=None)
    args = ap.parse_args()
    t0 = float(args.base_ts if args.base_ts is not None else time.time())
    rows: list[dict] = []
    t = t0
    # baseline normal
    rows.append({"start": t, "end": t + 3600, "scenario": "normal", "label": "normal"})
    t += 3600
    for sc in SCENARIOS:
        dur = 300.0
        label = "anomaly" if not sc.startswith("legit_") else "normal"
        rows.append({"start": t, "end": t + dur, "scenario": sc, "label": label})
        t += dur + 60.0
    write_labels(args.out, rows)
    print(f"wrote {len(rows)} rows → {args.out}")
    if not args.dry_run:
        print(
            "note: full MetricsCollector + simulations require operator scheduling; "
            "use --dry-run for CI / fixture generation"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
