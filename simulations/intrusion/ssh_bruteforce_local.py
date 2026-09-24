#!/usr/bin/env python3
"""Local SSH brute-force log simulator (writes synthetic auth lines to a temp log).

Does NOT attack real SSH. Feeds AuthWatcher-compatible lines for lab testing:
  python simulations/intrusion/ssh_bruteforce_local.py --out /tmp/fake_auth.log
Then point tests / custom AuthWatcher at that file, or use --emit-journal-style stdout.
"""

from __future__ import annotations

import argparse
import time


def main() -> int:
    p = argparse.ArgumentParser(description="Synthetic SSH fail lines for perimeter lab")
    p.add_argument("--ip", default="203.0.113.50", help="attacker IP (TEST-NET)")
    p.add_argument("--user", default="root")
    p.add_argument("--count", type=int, default=12)
    p.add_argument("--interval", type=float, default=0.05)
    p.add_argument("--out", default=None, help="append to file; default stdout")
    args = p.parse_args()
    lines = []
    for i in range(args.count):
        line = f"Failed password for {args.user} from {args.ip} port {40000+i} ssh2"
        lines.append(line)
        if args.out:
            with open(args.out, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            print(line, flush=True)
        time.sleep(args.interval)
    print(f"# wrote {len(lines)} fail lines for {args.ip}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
