#!/usr/bin/env python3
"""Local port-scan simulator: many source IPs via localhost reverse connections.

Safe: binds 127.0.0.1 only. Models 'many unique remotes -> one port' poorly on loopback
(same remote). Instead emits sequential syn-like connects to a local listener for net load,
and prints synthetic inbound events for rule-engine unit tests.

For RuleEngine port_scan lab, prefer tests/test_v2_perimeter.py which injects IPs directly.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time


def _listener(port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
            c.close()
        except socket.timeout:
            continue
        except OSError:
            break
    srv.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Localhost connect flood (lab)")
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--count", type=int, default=40)
    p.add_argument("--duration", type=float, default=5.0)
    args = p.parse_args()
    stop = threading.Event()
    t = threading.Thread(target=_listener, args=(args.port, stop), daemon=True)
    t.start()
    time.sleep(0.2)
    t0 = time.time()
    n = 0
    while n < args.count and time.time() - t0 < args.duration:
        try:
            s = socket.create_connection(("127.0.0.1", args.port), timeout=0.5)
            s.close()
            n += 1
        except OSError:
            pass
        time.sleep(0.02)
    stop.set()
    print(f"local connects={n} to 127.0.0.1:{args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
