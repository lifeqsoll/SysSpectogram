from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field


@dataclass
class HoneypotHit:
    remote: str
    port: int
    ts: float = field(default_factory=time.time)


class HoneypotListener:
    """Bind a high port and log inbound connects (lab/decoy)."""

    def __init__(self, port: int = 2222, bind: str = "0.0.0.0") -> None:
        self.port = port
        self.bind = bind
        self.hits: list[HoneypotHit] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.bind, self.port))
            srv.listen(32)
            srv.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    c, addr = srv.accept()
                    self.hits.append(HoneypotHit(remote=addr[0], port=self.port))
                    c.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            srv.close()
