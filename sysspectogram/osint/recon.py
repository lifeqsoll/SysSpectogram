from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sysspectogram.perimeter.enrich import enrich_ip_http

_TOOLS_BIN = Path(__file__).resolve().parents[2] / "tools" / "bin"


def _path_with_tools() -> str:
    parts = [
        str(_TOOLS_BIN),
        str(Path.home() / ".local" / "bin"),
        os.environ.get("PATH", ""),
    ]
    # dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for chunk in parts:
        for p in chunk.split(os.pathsep):
            if p and p not in seen:
                seen.add(p)
                out.append(p)
    return os.pathsep.join(out)


def _which(cmd: str) -> str | None:
    return shutil.which(cmd, path=_path_with_tools())


@dataclass
class ReconReport:
    ip: str
    ptr: str | None = None
    asn_org: str | None = None
    country: str | None = None
    dns_records: dict = field(default_factory=dict)
    ct_names: list[str] = field(default_factory=list)
    passive_dns: list[str] = field(default_factory=list)
    nmap: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def summary_text(self, host_id: str = "") -> str:
        lines = []
        if host_id:
            lines.append(f"[{host_id}]")
        lines.append(f"OSINT {self.ip}")
        if self.ptr:
            lines.append(f"PTR: {self.ptr}")
        if self.asn_org:
            lines.append(f"ORG: {self.asn_org}")
        if self.country:
            lines.append(f"CC: {self.country}")
        if self.dns_records:
            lines.append(f"DNS: {json.dumps(self.dns_records)[:300]}")
        if self.ct_names:
            lines.append("CT: " + ", ".join(self.ct_names[:8]))
        if self.passive_dns:
            lines.append("PDNS: " + ", ".join(self.passive_dns[:8]))
        ports = self.nmap.get("open_ports") or []
        if ports:
            lines.append("NMAP open: " + ", ".join(str(p) for p in ports[:20]))
        if self.nmap.get("unreliable"):
            lines.append("NMAP note: " + str(self.nmap.get("note") or "results look unreliable"))
        if self.errors:
            lines.append("notes: " + "; ".join(self.errors[:3]))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return asdict(self)


def _dns_lookup(name: str) -> dict:
    out: dict[str, list[str]] = {}
    dig = _which("dig")
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        vals: list[str] = []
        if dig:
            try:
                proc = subprocess.run(
                    [dig, "+short", rtype, name],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                    env={**os.environ, "PATH": _path_with_tools()},
                )
                vals = [x.strip() for x in proc.stdout.splitlines() if x.strip()]
            except (OSError, subprocess.SubprocessError):
                vals = []
        if not vals:
            try:
                import dns.resolver

                answers = dns.resolver.resolve(name, rtype)
                vals = [r.to_text() for r in answers][:10]
            except Exception:
                vals = []
        if vals:
            out[rtype] = vals[:10]
    return out


def ct_lookup(domain: str, timeout: float = 6.0, limit: int = 20) -> list[str]:
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": domain, "output": "json"})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sysspectogram/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        names: set[str] = set()
        if isinstance(data, list):
            for row in data:
                nv = str(row.get("name_value", ""))
                for part in nv.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part:
                        names.add(part.lower())
        return sorted(names)[:limit]
    except Exception as exc:
        return [f"ct_error:{exc}"]


def passive_dns_lookup(ip: str, api_url: str | None = None, timeout: float = 5.0) -> list[str]:
    """Optional passive DNS HTTP API. Expects JSON list or {data:[...]} of hostnames."""
    if not api_url:
        return []
    url = api_url.format(ip=urllib.parse.quote(ip))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sysspectogram/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        names: list[str] = []
        if isinstance(data, list):
            names = [str(x) for x in data]
        elif isinstance(data, dict):
            for key in ("data", "records", "names", "domains"):
                if isinstance(data.get(key), list):
                    names = [str(x) for x in data[key]]
                    break
        return [n.lower() for n in names if n][:30]
    except Exception:
        return []


def nmap_fast(ip: str, timeout_sec: int = 60) -> dict:
    nmap = _which("nmap")
    if nmap is None:
        # flatpak Zenmap fallback
        if shutil.which("flatpak"):
            nmap_cmd = ["flatpak", "run", "--command=nmap", "org.nmap.Zenmap"]
        else:
            return {"skipped": True, "reason": "nmap not installed", "open_ports": []}
    else:
        nmap_cmd = [nmap]
    try:
        # -sT: TCP connect (no root). Prefer over SYN when unprivileged.
        proc = subprocess.run(
            [*nmap_cmd, "-sT", "-Pn", "-F", "--max-retries", "1", "-T3", "-oG", "-", ip],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
            env={**os.environ, "PATH": _path_with_tools()},
        )
        ports: list[int] = []
        for line in proc.stdout.splitlines():
            if "Ports:" not in line:
                continue
            part = line.split("Ports:")[-1]
            for chunk in part.split(","):
                chunk = chunk.strip()
                if "/open/" in chunk:
                    try:
                        ports.append(int(chunk.split("/")[0]))
                    except ValueError:
                        pass
        return {
            "skipped": False,
            "open_ports": ports,
            "returncode": proc.returncode,
            "raw_tail": proc.stdout[-1500:],
            "unreliable": len(ports) >= 40,
            "note": (
                "too many open ports from -F; possible local MITM/VPN spoofing connect() results"
                if len(ports) >= 40
                else None
            ),
        }
    except Exception as exc:
        return {"skipped": True, "reason": str(exc), "open_ports": []}


def _nmap_lab_allowed(ip: str, lab_targets: list[str] | None) -> bool:
    allowed = set(lab_targets or ["127.0.0.1", "::1"])
    if ip in allowed:
        return True
    if ip in {"127.0.0.1", "::1"}:
        return True
    return False


def run_full_recon(
    ip: str,
    *,
    include_nmap: bool = False,
    include_ct: bool = True,
    passive_dns_url: str | None = None,
    lab_targets: list[str] | None = None,
    require_lab_for_nmap: bool = True,
) -> ReconReport:
    report = ReconReport(ip=ip)
    try:
        enrich = enrich_ip_http(ip)
        report.ptr = enrich.ptr
        report.asn_org = enrich.asn_org
        report.country = enrich.country
    except Exception as exc:
        report.errors.append(f"enrich:{exc}")

    domain = report.ptr
    if domain:
        try:
            report.dns_records = _dns_lookup(domain)
        except Exception as exc:
            report.errors.append(f"dns:{exc}")
        if include_ct:
            ct = ct_lookup(domain.split(":")[0])
            report.ct_names = [x for x in ct if not x.startswith("ct_error:")]
            for x in ct:
                if x.startswith("ct_error:"):
                    report.errors.append(x)

    try:
        report.passive_dns = passive_dns_lookup(ip, api_url=passive_dns_url)
    except Exception as exc:
        report.errors.append(f"pdns:{exc}")

    if include_nmap:
        if require_lab_for_nmap and not _nmap_lab_allowed(ip, lab_targets):
            report.nmap = {
                "skipped": True,
                "reason": "nmap blocked: target not in lab.nmap_targets (set recon.nmap + lab allowlist)",
                "open_ports": [],
            }
            report.errors.append(str(report.nmap["reason"]))
        else:
            report.nmap = nmap_fast(ip)
            if report.nmap.get("skipped"):
                report.errors.append(str(report.nmap.get("reason")))
    return report


def save_report(report: ReconReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(report.to_dict(), ensure_ascii=False) + "\n")
