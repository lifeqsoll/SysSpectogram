from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Alert:
    rule_id: str
    severity: str
    message: str
    ip: str | None = None
    port: int | None = None
    extras: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class Denylist:
    def __init__(self, paths: list[Path] | None = None) -> None:
        self.nets: list[ipaddress._BaseNetwork] = []
        self.ips: set[str] = set()
        for path in paths or []:
            self.load(path)

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if "/" in line:
                    self.nets.append(ipaddress.ip_network(line, strict=False))
                else:
                    self.ips.add(str(ipaddress.ip_address(line)))
            except ValueError:
                continue

    def hit(self, ip: str) -> bool:
        if ip in self.ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.nets)


class RuleEngine:
    def __init__(
        self,
        *,
        fail_threshold: int = 8,
        fail_window_sec: float = 60.0,
        scan_unique_ips: int = 8,
        scan_window_sec: float = 60.0,
        allowlist: set[str] | None = None,
        denylist: Denylist | None = None,
        known_login_ips: set[str] | None = None,
        alert_new_egress: bool = False,
        unusual_egress_ports: set[int] | None = None,
    ) -> None:
        self.fail_threshold = fail_threshold
        self.fail_window_sec = fail_window_sec
        self.scan_unique_ips = scan_unique_ips
        self.scan_window_sec = scan_window_sec
        self.allowlist = allowlist or set()
        self.denylist = denylist or Denylist()
        self.known_login_ips = known_login_ips or set()
        self.alert_new_egress = alert_new_egress
        self.unusual_egress_ports = unusual_egress_ports or {4444, 5555, 6666, 1337, 31337}
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._port_hits: dict[int, deque[tuple[float, str]]] = defaultdict(deque)
        self._seen_egress: set[str] = set()
        self._cooldown: dict[str, float] = {}
        self._egress_bootstrapped = False

    def seed_egress(self, keys: list[str]) -> None:
        self._seen_egress.update(keys)
        self._egress_bootstrapped = True

    def _cool(self, key: str, sec: float = 60.0) -> bool:
        now = time.time()
        last = self._cooldown.get(key, 0.0)
        if now - last < sec:
            return False
        self._cooldown[key] = now
        return True

    def on_auth_fail(self, ip: str, user: str = "") -> Alert | None:
        if ip in self.allowlist:
            return None
        now = time.time()
        q = self._fails[ip]
        q.append(now)
        while q and now - q[0] > self.fail_window_sec:
            q.popleft()
        if len(q) >= self.fail_threshold and self._cool(f"brute:{ip}"):
            return Alert(
                rule_id="bruteforce_ssh",
                severity="critical",
                message=f"SSH brute suspected from {ip}: {len(q)} fails / {self.fail_window_sec:.0f}s",
                ip=ip,
                extras={"fails": len(q), "user": user},
            )
        return None

    def on_auth_accepted(self, ip: str, user: str = "") -> Alert | None:
        if ip in self.allowlist or ip in self.known_login_ips:
            self.known_login_ips.add(ip)
            return None
        if self._cool(f"newlogin:{ip}", 300.0):
            alert = Alert(
                rule_id="new_login_source",
                severity="high",
                message=f"New SSH login source {ip} user={user}",
                ip=ip,
                extras={"user": user},
            )
            self.known_login_ips.add(ip)
            return alert
        return None

    def on_inbound(self, ip: str, port: int) -> Alert | None:
        if ip in self.allowlist:
            return None
        now = time.time()
        q = self._port_hits[port]
        q.append((now, ip))
        while q and now - q[0][0] > self.scan_window_sec:
            q.popleft()
        unique = {x[1] for x in q}
        if len(unique) >= self.scan_unique_ips and self._cool(f"scan:{port}"):
            return Alert(
                rule_id="port_scan_suspected",
                severity="high",
                message=f"Port scan suspected on :{port}: {len(unique)} unique IPs / {self.scan_window_sec:.0f}s",
                ip=ip,
                port=port,
                extras={"unique_ips": len(unique)},
            )
        return None

    def on_egress(self, ip: str, port: int, proc: str | None = None) -> Alert | None:
        if ip in self.allowlist:
            return None
        key = f"{ip}:{port}"
        if self.denylist.hit(ip):
            if self._cool(f"egressdl:{ip}"):
                return Alert(
                    rule_id="egress_denylist_hit",
                    severity="critical",
                    message=f"Egress to denylisted {ip}:{port}" + (f" ({proc})" if proc else ""),
                    ip=ip,
                    port=port,
                    extras={"process": proc},
                )
        if not self._egress_bootstrapped:
            self._seen_egress.add(key)
            return None
        if key not in self._seen_egress:
            self._seen_egress.add(key)
            unusual = port in self.unusual_egress_ports
            if (self.alert_new_egress or unusual) and self._cool(f"egressnew:{ip}", 120.0):
                return Alert(
                    rule_id="suspicious_egress",
                    severity="high" if unusual else "medium",
                    message=f"New external egress {ip}:{port}" + (f" ({proc})" if proc else ""),
                    ip=ip,
                    port=port,
                    extras={"process": proc, "unusual_port": unusual},
                )
        return None

    def on_suspicious_dns(self, name: str) -> Alert | None:
        name = name.lower()
        if self._cool(f"dns:{name}", 120.0):
            return Alert(
                rule_id="suspicious_dns",
                severity="high",
                message=f"Suspicious DNS query: {name}",
                extras={"domain": name},
            )
        return None
