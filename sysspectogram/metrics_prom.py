"""Minimal Prometheus text exposition (stdlib only, localhost by default)."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class PromRegistry:
    """Thread-safe gauge/counter store → Prometheus text format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._gauges: dict[str, float] = {}
        self._counters: dict[str, float] = {}
        self._labels: dict[str, dict[str, str]] = {}
        self._help: dict[str, str] = {}
        self._started = time.time()

    def set_gauge(self, name: str, value: float, *, help_text: str = "", labels: dict[str, str] | None = None) -> None:
        with self._lock:
            self._gauges[name] = float(value)
            if help_text:
                self._help[name] = help_text
            if labels:
                self._labels[name] = dict(labels)

    def inc_counter(self, name: str, amount: float = 1.0, *, help_text: str = "") -> None:
        with self._lock:
            self._counters[name] = float(self._counters.get(name, 0.0) + amount)
            if help_text:
                self._help[name] = help_text

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            lines.append(f"# HELP sysspectogram_up 1 while metrics process is alive")
            lines.append(f"# TYPE sysspectogram_up gauge")
            lines.append("sysspectogram_up 1")
            lines.append(f"# HELP sysspectogram_uptime_seconds Process uptime")
            lines.append(f"# TYPE sysspectogram_uptime_seconds gauge")
            lines.append(f"sysspectogram_uptime_seconds {time.time() - self._started:.3f}")
            for name, val in sorted(self._gauges.items()):
                help_t = self._help.get(name, name)
                lines.append(f"# HELP {name} {help_t}")
                lines.append(f"# TYPE {name} gauge")
                labs = self._labels.get(name) or {}
                if labs:
                    lab = ",".join(f'{k}="{v}"' for k, v in labs.items())
                    lines.append(f"{name}{{{lab}}} {val}")
                else:
                    lines.append(f"{name} {val}")
            for name, val in sorted(self._counters.items()):
                help_t = self._help.get(name, name)
                lines.append(f"# HELP {name} {help_t}")
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name} {val}")
        return "\n".join(lines) + "\n"


GLOBAL_PROM = PromRegistry()


def start_prom_server(
    host: str = "127.0.0.1",
    port: int = 9108,
    *,
    registry: PromRegistry | None = None,
) -> ThreadingHTTPServer:
    reg = registry or GLOBAL_PROM

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] not in ("/metrics", "/"):
                self.send_response(404)
                self.end_headers()
                return
            body = reg.render().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    httpd = ThreadingHTTPServer((host, int(port)), Handler)
    t = threading.Thread(target=httpd.serve_forever, name="prom-metrics", daemon=True)
    t.start()
    return httpd
