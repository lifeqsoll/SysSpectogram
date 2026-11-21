from __future__ import annotations

import ipaddress
import logging
import time
import warnings
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


ALERT_SCHEMA_VERSION = 1


@dataclass
class Alert:
    rule_id: str
    severity: str
    message: str
    ip: str | None = None
    port: int | None = None
    extras: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    schema_version: int = ALERT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": int(self.schema_version),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "ip": self.ip,
            "port": self.port,
            "extras": dict(self.extras or {}),
            "ts": float(self.ts),
        }


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


def resolve_public_ports(
    configured: list[int] | set[int] | None,
    listening_public: set[int] | None = None,
    *,
    always_include: set[int] | None = None,
) -> set[int]:
    """Public service ports: config override, else wildcard listeners + 80/443."""
    base = set(always_include or {80, 443})
    if configured is not None:
        return {int(p) for p in configured} | base
    return set(listening_public or ()) | base


class RuleEngine:
    def __init__(
        self,
        *,
        fail_threshold: int = 8,
        fail_window_sec: float = 60.0,
        scan_unique_ports: int | None = None,
        scan_unique_ips: int | None = None,
        scan_window_sec: float = 60.0,
        allowlist: set[str] | None = None,
        denylist: Denylist | None = None,
        known_login_ips: set[str] | None = None,
        alert_new_egress: bool = False,
        unusual_egress_ports: set[int] | None = None,
        v6_brute_prefix: int = 0,
        public_ports: set[int] | None = None,
        listening_ports: set[int] | None = None,
        flood_enabled: bool = True,
        flood_ewma_alpha: float = 0.05,
        flood_mult: float = 5.0,
        flood_min_ip_per_min: float = 2000.0,
        flood_cooldown_sec: float = 900.0,
        closed_port_weight: float = 2.0,
    ) -> None:
        self.fail_threshold = fail_threshold
        self.fail_window_sec = fail_window_sec
        # Prefer scan_unique_ports; scan_unique_ips is a deprecated alias.
        if scan_unique_ports is None and scan_unique_ips is not None:
            warnings.warn(
                "perimeter.scan_unique_ips is deprecated; use scan_unique_ports "
                "(unique destination ports per source IP). Mapping alias → scan_unique_ports.",
                DeprecationWarning,
                stacklevel=2,
            )
            log.warning(
                "perimeter.scan_unique_ips is deprecated; use scan_unique_ports (got %s)",
                scan_unique_ips,
            )
            scan_unique_ports = int(scan_unique_ips)
        self.scan_unique_ports = int(scan_unique_ports if scan_unique_ports is not None else 10)
        # Keep attribute for older callers/tests that still read it.
        self.scan_unique_ips = self.scan_unique_ports
        self.scan_window_sec = scan_window_sec
        self.allowlist = allowlist or set()
        self.denylist = denylist or Denylist()
        self.known_login_ips = known_login_ips or set()
        self.alert_new_egress = alert_new_egress
        self.unusual_egress_ports = unusual_egress_ports or {4444, 5555, 6666, 1337, 31337}
        self.v6_brute_prefix = int(v6_brute_prefix or 0)
        self.public_ports = set(public_ports or {80, 443})
        self.listening_ports = set(listening_ports or ())
        self.flood_enabled = flood_enabled
        self.flood_ewma_alpha = float(flood_ewma_alpha)
        self.flood_mult = float(flood_mult)
        self.flood_min_ip_per_min = float(flood_min_ip_per_min)
        self.flood_cooldown_sec = float(flood_cooldown_sec)
        self.closed_port_weight = float(closed_port_weight)
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        # Source IP → (ts, dest_port) for horizontal port scans.
        self._src_ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # Public port → (ts, src_ip) for inbound flood baseline.
        self._port_hits: dict[int, deque[tuple[float, str]]] = defaultdict(deque)
        self._flood_ewma: dict[int, float] = {}
        self._flood_samples: dict[int, int] = defaultdict(int)
        self._seen_egress: set[str] = set()
        self._cooldown: dict[str, float] = {}
        self._egress_bootstrapped = False

    def set_public_ports(self, ports: set[int]) -> None:
        self.public_ports = set(ports)

    def set_listening_ports(self, ports: set[int]) -> None:
        self.listening_ports = set(ports)

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

    def _fail_bucket(self, ip: str) -> str:
        prefix = int(self.v6_brute_prefix or 0)
        if prefix <= 0 or ":" not in str(ip):
            return ip
        try:
            from ipaddress import ip_network

            return str(ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            return ip

    def on_auth_fail(self, ip: str, user: str = "") -> Alert | None:
        if ip in self.allowlist:
            return None
        now = time.time()
        key = self._fail_bucket(ip)
        q = self._fails[key]
        q.append(now)
        while q and now - q[0] > self.fail_window_sec:
            q.popleft()
        if len(q) >= self.fail_threshold and self._cool(f"brute:{key}"):
            ban_target = key if key != ip else ip
            return Alert(
                rule_id="bruteforce_ssh",
                severity="critical",
                message=(
                    f"SSH brute suspected from {ban_target}: {len(q)} fails / "
                    f"{self.fail_window_sec:.0f}s (last={ip})"
                ),
                ip=ban_target,
                extras={"fails": len(q), "user": user, "last_ip": ip, "bucket": key},
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

    def _weighted_unique_ports(self, hits: deque[tuple[float, int]]) -> float:
        """Count unique dest ports; closed/non-listening ports weigh more."""
        score = 0.0
        seen: set[int] = set()
        for _ts, port in hits:
            if port in seen:
                continue
            seen.add(port)
            if self.listening_ports and port not in self.listening_ports:
                score += self.closed_port_weight
            elif port not in self.public_ports and port not in self.listening_ports:
                score += self.closed_port_weight
            else:
                score += 1.0
        return score

    def _check_flood(self, ip: str, port: int, now: float) -> Alert | None:
        if not self.flood_enabled or port not in self.public_ports:
            return None
        q = self._port_hits[port]
        q.append((now, ip))
        while q and now - q[0][0] > 60.0:
            q.popleft()
        unique = {x[1] for x in q}
        # Unique IPs observed in the last 60s ≈ IP/min.
        rate = float(len(unique))
        prev = self._flood_ewma.get(port)
        samples = self._flood_samples[port]
        # Compare against the pre-update baseline so a spike is not diluted into EWMA first.
        baseline = prev if prev is not None else rate
        alert: Alert | None = None
        if samples >= 30 and prev is not None:
            threshold = max(baseline * self.flood_mult, self.flood_min_ip_per_min)
            if rate >= threshold and rate >= self.flood_min_ip_per_min:
                if self._cool(f"flood:{port}", self.flood_cooldown_sec):
                    alert = Alert(
                        rule_id="inbound_flood_suspected",
                        severity="medium",
                        message=(
                            f"Inbound flood suspected on :{port}: {rate:.0f} unique IPs/min "
                            f"(baseline≈{baseline:.0f}, ×{self.flood_mult:g})"
                        ),
                        ip=None,
                        port=port,
                        extras={
                            "unique_ips": int(rate),
                            "ewma": baseline,
                            "threshold": threshold,
                        },
                    )
        alpha = self.flood_ewma_alpha
        if prev is None:
            self._flood_ewma[port] = rate
        elif alert is not None:
            # Freeze baseline during a confirmed flood.
            self._flood_ewma[port] = prev
        else:
            soft_cap = max(prev * self.flood_mult, self.flood_min_ip_per_min)
            if rate < soft_cap:
                self._flood_ewma[port] = alpha * rate + (1.0 - alpha) * prev
            # else: approaching spike — freeze so EWMA does not chase the attack
        self._flood_samples[port] = samples + 1
        return alert

    def on_inbound(self, ip: str, port: int) -> Alert | None:
        """Detect horizontal port scans (one source → many ports).

        Many distinct IPs hitting one public port is normal web traffic and never
        raises port_scan_suspected. Optional inbound_flood_suspected covers spikes.
        """
        if ip in self.allowlist:
            return None
        now = time.time()

        flood = self._check_flood(ip, port, now)

        q = self._src_ports[ip]
        q.append((now, int(port)))
        while q and now - q[0][0] > self.scan_window_sec:
            q.popleft()
        score = self._weighted_unique_ports(q)
        unique_ports = {p for _ts, p in q}
        if score >= self.scan_unique_ports and self._cool(f"scan:{ip}"):
            return Alert(
                rule_id="port_scan_suspected",
                severity="high",
                message=(
                    f"Port scan suspected from {ip}: {len(unique_ports)} unique ports / "
                    f"{self.scan_window_sec:.0f}s (score={score:.1f})"
                ),
                ip=ip,
                port=port,
                extras={
                    "unique_ports": len(unique_ports),
                    "score": score,
                    "ports": sorted(unique_ports)[:40],
                },
            )
        return flood

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
