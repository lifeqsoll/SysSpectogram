"""Multi-sink alert fan-out (file / syslog / https). Fail-open per sink."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from sysspectogram.audit.report import append_jsonl

log = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def _is_private_host(host: str) -> bool:
    """Literal IP / localhost-style name check (no DNS). Prefer `_sink_host_blocked`."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h == "localhost":
        return True
    if h.endswith(".local") or h.endswith(".localhost"):
        return True
    try:
        return _is_blocked_ip(h)
    except ValueError:
        return False


def _sink_host_blocked(host: str) -> bool:
    """True if host is private as a literal IP or any resolved A/AAAA is blocked.

    Hostname-only checks are insufficient (e.g. 169.254.169.254.nip.io).
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(".local") or h.endswith(".localhost"):
        return True
    try:
        return _is_blocked_ip(h)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None)
    except OSError as exc:
        raise RuntimeError(f"cannot resolve sink host {h}: {exc}") from exc
    if not infos:
        raise RuntimeError(f"cannot resolve sink host {h}")
    for info in infos:
        addr = info[4][0]
        try:
            if _is_blocked_ip(addr):
                return True
        except ValueError:
            continue
    return False


class AlertFanout:
    def __init__(
        self,
        sinks: list[Mapping[str, Any]] | None = None,
        *,
        allow_private_sinks: bool = False,
        strict_secrets: bool = True,
    ) -> None:
        self.sinks: list[dict[str, Any]] = [dict(s) for s in (sinks or [])]
        self.allow_private_sinks = bool(allow_private_sinks)
        self.strict_secrets = bool(strict_secrets)

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None) -> "AlertFanout":
        cfg = dict(config or {})
        alerts = dict(cfg.get("alerts") or {})
        sinks = list(alerts.get("sinks") or [])
        if not sinks:
            path = (cfg.get("perimeter") or {}).get("jsonl_out") or "reports/alerts.jsonl"
            sinks = [{"type": "file", "path": path}]
        return cls(
            sinks,
            allow_private_sinks=bool(alerts.get("allow_private_sinks", False)),
            strict_secrets=bool(alerts.get("strict_secrets", True)),
        )

    def emit(self, event: dict[str, Any]) -> None:
        payload = dict(event)
        payload.setdefault("ts", _now())
        for sink in self.sinks:
            kind = str(sink.get("type") or "file").lower()
            try:
                if kind == "file":
                    self._file(sink, payload)
                elif kind == "syslog":
                    self._syslog(sink, payload)
                elif kind == "https":
                    self._https(sink, payload)
                else:
                    log.warning("unknown alert sink type=%s", kind)
            except Exception as exc:  # noqa: BLE001 — fail-open
                log.warning("alert sink %s failed: %s", kind, exc)

    def _file(self, sink: Mapping[str, Any], payload: dict[str, Any]) -> None:
        path = Path(str(sink.get("path") or "reports/alerts.jsonl"))
        append_jsonl(path, payload)

    def _syslog(self, sink: Mapping[str, Any], payload: dict[str, Any]) -> None:
        host = str(sink.get("host") or "127.0.0.1")
        if not self.allow_private_sinks and _sink_host_blocked(host):
            # localhost syslog is common on same host — allow 127.0.0.1/::1 only when
            # explicitly same-box; still block link-local / RFC1918 unless opted in.
            if host not in {"127.0.0.1", "::1", "localhost"}:
                raise RuntimeError(
                    f"syslog host {host} looks private; set alerts.allow_private_sinks: true"
                )
        port = int(sink.get("port") or 514)
        transport = str(sink.get("transport") or "udp").lower()
        facility = int(sink.get("facility") or 16)
        severity = int(sink.get("severity") or 5)
        pri = facility * 8 + severity
        app = str(sink.get("app") or "sysspectogram")
        msg = json.dumps(payload, ensure_ascii=False)
        line = f"<{pri}>1 {_now()} - {app} - - - {msg}\n".encode("utf-8")
        if transport == "tls":
            raw = socket.create_connection((host, port), timeout=float(sink.get("timeout", 3)))
            ctx = ssl.create_default_context()
            ca = sink.get("tls_ca")
            if ca:
                ctx.load_verify_locations(cafile=str(ca))
            if sink.get("insecure"):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                sock.sendall(line)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(float(sink.get("timeout", 2)))
                sock.sendto(line, (host, port))
            finally:
                sock.close()

    def _https(self, sink: Mapping[str, Any], payload: dict[str, Any]) -> None:
        url = str(sink.get("url") or "")
        if not url:
            raise ValueError("https sink requires url")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"https"}:
            raise RuntimeError("https sink requires https:// URL")
        host = parsed.hostname or ""
        if not self.allow_private_sinks and _sink_host_blocked(host):
            raise RuntimeError(
                f"https sink host {host} looks private/link-local; "
                "set alerts.allow_private_sinks: true to override"
            )
        headers = {"Content-Type": "application/json"}
        token_env = sink.get("token_env")
        if token_env:
            token = os.environ.get(str(token_env), "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        if sink.get("token"):
            if self.strict_secrets:
                raise RuntimeError(
                    "inline sink token refused (alerts.strict_secrets); use token_env"
                )
            headers["Authorization"] = f"Bearer {sink['token']}"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        timeout = float(sink.get("timeout", 5))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp.read(64)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"https sink HTTP {exc.code}") from exc
