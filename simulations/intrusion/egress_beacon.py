#!/usr/bin/env python3
"""Egress beacon simulator: connect to denylisted TEST-NET IP (or local sink).

Safe defaults use 203.0.113.66 (documentation range) which will fail to connect
but still appears briefly in SYN_SENT for /proc watchers. Prefer --local-sink
to open a real localhost connection tagged as egress-like for process maps.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time


def _sink(port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    srv.settimeout(1.0)
    conns = []
    while not stop.is_set():
        try:
            c, _ = srv.accept()
            conns.append(c)
        except socket.timeout:
            continue
        except OSError:
            break
    for c in conns:
        try:
            c.close()
        except OSError:
            pass
    srv.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Egress beacon lab")
    p.add_argument("--target", default="203.0.113.66")
    p.add_argument("--port", type=int, default=4444)
    p.add_argument("--duration", type=float, default=8.0)
    p.add_argument("--local-sink", action="store_true", help="beacon to 127.0.0.1 instead")
    p.add_argument("--lab", action="store_true", help="acknowledge intentional lab run")
    args = p.parse_args()
    if not args.lab and not args.local_sink:
        print("Refusing: pass --lab for external TEST-NET attempts, or --local-sink")
        return 2

    stop = threading.Event()
    host = "127.0.0.1" if args.local_sink else args.target
    if args.local_sink:
        threading.Thread(target=_sink, args=(args.port, stop), daemon=True).start()
        time.sleep(0.2)

    socks = []
    t0 = time.time()
    print(f"beacon -> {host}:{args.port} for {args.duration}s")
    while time.time() - t0 < args.duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((host, args.port))
            socks.append(s)
        except OSError:
            pass
        time.sleep(0.5)
    stop.set()
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
