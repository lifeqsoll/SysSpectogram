from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from sysspectogram.config import load_config


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lab nmap only against allowlisted targets")
    p.add_argument("target")
    p.add_argument("--config", default=None)
    p.add_argument("--lab", action="store_true", required=True)
    args = p.parse_args(argv)
    cfg = load_config(args.config)
    allowed = set(cfg.get("lab", {}).get("nmap_targets") or [])
    if args.target not in allowed and not any(
        args.target.startswith(a.split("/")[0]) for a in allowed if "/" in a
    ):
        # also allow exact CIDR membership soft check skipped; require exact list match or 127.0.0.1
        if args.target not in {"127.0.0.1", "::1"} and args.target not in allowed:
            print(f"refusing: {args.target} not in lab.nmap_targets")
            return 2
    cmd = ["nmap", "-F", "--max-retries", "1", "-T3", args.target]
    print("lab nmap:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
