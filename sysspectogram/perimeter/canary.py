"""Dark-port canaries: any connect sets recon_score 1.0 (rule_id canary_hit)."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field


@dataclass
class CanaryHit:
    remote: str
    port: int
    ts: float = field(default_factory=time.time)


class CanaryBank:
    """Listen on unused TCP ports; treat any inbound as high-confidence probe."""

    def __init__(self, ports: list[int], bind: str = "0.0.0.0") -> None:
        self.ports = [int(p) for p in ports if int(p) > 0]
        self.bind = bind
        self.hits: list[CanaryHit] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> list[int]:
        if self._threads:
            return list(self.ports)
        self._stop.clear()
        ok: list[int] = []
        for port in self.ports:
            t = threading.Thread(
                target=self._run_one, args=(port,), daemon=True, name=f"canary-{port}"
            )
            t.start()
            self._threads.append(t)
            ok.append(port)
        return ok

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._threads.clear()

    def _run_one(self, port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.bind, port))
            srv.listen(16)
            srv.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    c, addr = srv.accept()
                    self.hits.append(CanaryHit(remote=addr[0], port=port))
                    try:
                        c.close()
                    except OSError:
                        pass
                except socket.timeout:
                    continue
                except OSError:
                    break
        except OSError:
            return
        finally:
            try:
                srv.close()
            except OSError:
                pass
