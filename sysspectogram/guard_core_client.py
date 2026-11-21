"""Unix JSONL client for `sysspectogram-guard-core serve` (rules / risk / ban)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from sysspectogram.guard_core_bridge import find_bin
from sysspectogram.perimeter.rules import Alert


class GuardCoreClient:
    def __init__(self, socket_path: str | Path, *, timeout: float = 3.0) -> None:
        self.socket_path = Path(socket_path)
        self.timeout = float(timeout)

    def available(self) -> bool:
        try:
            return self.socket_path.is_socket()
        except OSError:
            return False

    def call(self, op: str, **fields: Any) -> dict[str, Any]:
        req = {"op": op, **fields}
        raw = json.dumps(req, ensure_ascii=False) + "\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
            sock.sendall(raw.encode("utf-8"))
            chunks: list[bytes] = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        text = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not text:
            return {"ok": False, "error": "empty"}
        try:
            data = json.loads(text.splitlines()[0])
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": str(exc)}
        return data if isinstance(data, dict) else {"ok": False, "error": "bad"}

    def _alert(self, payload: dict[str, Any] | None) -> Alert | None:
        if not payload:
            return None
        sv = payload.get("schema_version")
        try:
            schema_version = int(sv) if sv is not None else 1
        except (TypeError, ValueError):
            schema_version = 1
        return Alert(
            rule_id=str(payload.get("rule_id") or ""),
            severity=str(payload.get("severity") or "medium"),
            message=str(payload.get("message") or ""),
            ip=payload.get("ip"),
            port=int(payload["port"]) if payload.get("port") is not None else None,
            extras=dict(payload.get("extras") or {}),
            ts=float(payload.get("ts") or time.time()),
            schema_version=schema_version,
        )

    def on_auth_fail(self, ip: str, user: str = "") -> Alert | None:
        r = self.call("on_auth_fail", ip=ip, user=user)
        return self._alert(r.get("alert") if r.get("ok") else None)

    def on_auth_accepted(self, ip: str, user: str = "") -> Alert | None:
        r = self.call("on_auth_accepted", ip=ip, user=user)
        return self._alert(r.get("alert") if r.get("ok") else None)

    def on_inbound(self, ip: str, port: int) -> Alert | None:
        r = self.call("on_inbound", ip=ip, port=int(port))
        return self._alert(r.get("alert") if r.get("ok") else None)

    def on_egress(self, ip: str, port: int, proc: str | None = None) -> Alert | None:
        r = self.call("on_egress", ip=ip, port=int(port), proc=proc)
        return self._alert(r.get("alert") if r.get("ok") else None)

    def on_suspicious_dns(self, name: str) -> Alert | None:
        r = self.call("on_suspicious_dns", name=name)
        return self._alert(r.get("alert") if r.get("ok") else None)

    def decide_risk(self, **kwargs: Any) -> dict[str, Any] | None:
        r = self.call("decide_risk", **kwargs)
        if not r.get("ok"):
            return None
        d = r.get("decision")
        return d if isinstance(d, dict) else None

    def ban(self, ip: str, ttl_sec: int = 3600, *, dry_run: bool = False) -> str:
        r = self.call("ban", ip=ip, ttl_sec=int(ttl_sec), dry_run=bool(dry_run))
        return str(r.get("message") or r.get("error") or "ban failed")

    def configure_rules(self, **kwargs: Any) -> bool:
        r = self.call("configure_rules", **kwargs)
        return bool(r.get("ok"))


def ensure_guard_core_serve(
    socket_path: str | Path,
    *,
    bin_path: str | Path | None = None,
) -> subprocess.Popen | None:
    """Start `guard-core serve` if the socket is missing. Returns the Popen or None."""
    sock = Path(socket_path)
    if sock.is_socket():
        return None
    exe = Path(bin_path) if bin_path else find_bin()
    if exe is None:
        return None
    sock.parent.mkdir(parents=True, exist_ok=True)
    try:
        return subprocess.Popen(
            [str(exe), "serve", "--socket", str(sock)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return None


class RemoteRuleEngine:
    """Drop-in RuleEngine surface backed by guard-core serve."""

    def __init__(self, client: GuardCoreClient, *, fallback: Any = None) -> None:
        self.client = client
        self.fallback = fallback
        self.allowlist: set[str] = set()
        self.known_login_ips: set[str] = set()
        self.public_ports: set[int] = {80, 443}
        self.listening_ports: set[int] = set()
        # Mirror attributes some callers read.
        self.fail_threshold = 8
        self.scan_unique_ports = 10
        self.scan_unique_ips = 10
        self.flood_enabled = True

    def set_public_ports(self, ports: set[int]) -> None:
        self.public_ports = set(ports)
        self.client.configure_rules(public_ports=sorted(self.public_ports))
        if self.fallback is not None:
            self.fallback.set_public_ports(ports)

    def set_listening_ports(self, ports: set[int]) -> None:
        self.listening_ports = set(ports)
        self.client.configure_rules(listening_ports=sorted(self.listening_ports))
        if self.fallback is not None:
            self.fallback.set_listening_ports(ports)

    def seed_egress(self, keys: list[str]) -> None:
        if self.fallback is not None:
            self.fallback.seed_egress(keys)

    def on_auth_fail(self, ip: str, user: str = "") -> Alert | None:
        try:
            return self.client.on_auth_fail(ip, user)
        except OSError:
            return self.fallback.on_auth_fail(ip, user) if self.fallback else None

    def on_auth_accepted(self, ip: str, user: str = "") -> Alert | None:
        try:
            return self.client.on_auth_accepted(ip, user)
        except OSError:
            return self.fallback.on_auth_accepted(ip, user) if self.fallback else None

    def on_inbound(self, ip: str, port: int) -> Alert | None:
        try:
            return self.client.on_inbound(ip, port)
        except OSError:
            return self.fallback.on_inbound(ip, port) if self.fallback else None

    def on_egress(self, ip: str, port: int, proc: str | None = None) -> Alert | None:
        try:
            return self.client.on_egress(ip, port, proc)
        except OSError:
            return self.fallback.on_egress(ip, port, proc) if self.fallback else None

    def on_suspicious_dns(self, name: str) -> Alert | None:
        try:
            return self.client.on_suspicious_dns(name)
        except OSError:
            return self.fallback.on_suspicious_dns(name) if self.fallback else None


_risk_client: GuardCoreClient | None = None


def set_risk_client(client: GuardCoreClient | None) -> None:
    global _risk_client
    _risk_client = client


def decide_risk_via_core(**kwargs: Any) -> Any | None:
    """Return a RiskDecision-like object from guard-core, or None on failure."""
    if _risk_client is None or not _risk_client.available():
        return None
    try:
        d = _risk_client.decide_risk(**kwargs)
    except OSError:
        return None
    if not d:
        return None
    from sysspectogram.risk import RiskDecision

    return RiskDecision(
        risk=float(d.get("risk") or 0.0),
        is_anomaly=bool(d.get("is_anomaly")),
        reason=str(d.get("reason") or "none"),
        baseline_z=(float(d["baseline_z"]) if d.get("baseline_z") is not None else None),
        baseline_promoted=bool(d.get("baseline_promoted")),
    )
