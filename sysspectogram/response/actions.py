from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass


@dataclass
class BanRecord:
    ip: str
    created: float
    expires: float | None
    comment: str
    handle: int | None = None
    backend: str = "memory"


class NftBackend:
    """nft/iptables ban manager with handle-based unban and TTL."""

    def __init__(self, table: str = "inet", chain: str = "sysspectogram") -> None:
        self.table = table
        self.chain = chain
        self.bans: dict[str, BanRecord] = {}
        self._ensure_chain()

    def _run(self, cmd: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)

    def _ensure_chain(self) -> None:
        if not shutil.which("nft"):
            return
        self._run(["nft", "add", "table", "inet", "sysspectogram"])
        self._run(
            [
                "nft",
                "add",
                "chain",
                "inet",
                "sysspectogram",
                "input",
                "{ type filter hook input priority 0 ; }",
            ]
        )

    def _find_nft_handle(self, ip: str) -> int | None:
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        if code != 0:
            return None
        # ip saddr 1.2.3.4 drop comment "..." # handle 12
        for line in out.splitlines():
            if ip not in line or "handle" not in line:
                continue
            if f"saddr {ip}" not in line and f"ip saddr {ip}" not in line:
                # also match comment containing ip
                if f"sysspectogram:{ip}:" not in line:
                    continue
            m = re.search(r"#\s*handle\s+(\d+)", line)
            if m:
                return int(m.group(1))
        return None

    def ban_ip(self, ip: str, ttl_sec: float | None = 3600.0, dry_run: bool = False) -> str:
        # replace existing
        if ip in self.bans and not dry_run:
            self.unban_ip(ip, dry_run=False)
        expires = None if ttl_sec is None else time.time() + ttl_sec
        comment = f"sysspectogram:{ip}:{int(expires or 0)}"
        if dry_run:
            self.bans[ip] = BanRecord(ip, time.time(), expires, comment, None, "dry-run")
            return f"dry-run ban {ip} ttl={ttl_sec}"
        handle = None
        backend = "memory"
        if shutil.which("nft"):
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "ip",
                    "saddr",
                    ip,
                    "drop",
                    "comment",
                    comment,
                ]
            )
            if code != 0:
                return f"nft failed: {out.strip()}"
            handle = self._find_nft_handle(ip)
            backend = "nft"
        elif shutil.which("iptables"):
            code, out = self._run(
                [
                    "iptables",
                    "-I",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                ]
            )
            if code != 0:
                return f"iptables failed: {out.strip()}"
            backend = "iptables"
        else:
            return "no nft/iptables available"
        self.bans[ip] = BanRecord(ip, time.time(), expires, comment, handle, backend)
        return f"banned {ip} ttl={ttl_sec} backend={backend} handle={handle}"

    def unban_ip(self, ip: str, dry_run: bool = False) -> str:
        rec = self.bans.pop(ip, None)
        if dry_run:
            return f"dry-run unban {ip}"
        if shutil.which("nft"):
            handle = rec.handle if rec else None
            if handle is None:
                handle = self._find_nft_handle(ip)
            if handle is not None:
                code, out = self._run(
                    ["nft", "delete", "rule", "inet", "sysspectogram", "input", "handle", str(handle)]
                )
                if code != 0:
                    return f"nft unban failed handle={handle}: {out.strip()}"
                return f"unbanned {ip} nft handle={handle}"
            return f"unban: no nft handle found for {ip} (memory cleared)"
        if shutil.which("iptables"):
            # delete matching DROP rules for source (may need multiple -D)
            for _ in range(8):
                code, _ = self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                if code != 0:
                    break
            return f"unban attempted for {ip} (iptables)"
        return f"unban recorded {ip}"

    def list_bans(self) -> list[BanRecord]:
        now = time.time()
        expired = [ip for ip, b in self.bans.items() if b.expires and b.expires <= now]
        for ip in expired:
            self.unban_ip(ip)
        return list(self.bans.values())

    def apply_lockdown(self, dry_run: bool = False) -> str:
        """Drop new inbound TCP except established/related and allowlisted later via unban/allow."""
        if dry_run:
            return "dry-run lockdown: would drop new inbound tcp on inet sysspectogram input"
        if not shutil.which("nft"):
            return "nft required for lockdown"
        self._ensure_chain()
        # ct state established,related accept; then drop new tcp (except we keep allow via not adding yet)
        self._run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "ct",
                "state",
                "established,related",
                "accept",
                "comment",
                "sysspectogram:lockdown:est",
            ]
        )
        code, out = self._run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "tcp",
                "flags",
                "syn",
                "/",
                "syn",
                "drop",
                "comment",
                "sysspectogram:lockdown:syn",
            ]
        )
        if code != 0:
            return f"lockdown failed: {out.strip()}"
        return "lockdown nft rules applied (SYN drop; established allowed)"

    def shield_port(self, port: int, ttl_sec: float = 3600.0, dry_run: bool = False) -> str:
        if dry_run:
            return f"dry-run shield port {port} for {ttl_sec}s"
        if shutil.which("nft"):
            comment = f"sysspectogram:port:{port}:{int(time.time() + ttl_sec)}"
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "tcp",
                    "dport",
                    str(port),
                    "drop",
                    "comment",
                    comment,
                ]
            )
            if code != 0:
                return f"shield failed: {out.strip()}"
            return f"shielded port {port}"
        return "nft required for shield_port"


def kill_pid(pid: int, dry_run: bool = False) -> str:
    if pid <= 1:
        return "refusing to kill pid<=1"
    if dry_run:
        return f"dry-run kill {pid}"
    try:
        import os
        import signal

        os.kill(pid, signal.SIGTERM)
        time.sleep(0.4)
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            return f"killed {pid} (SIGKILL)"
        except ProcessLookupError:
            return f"terminated {pid}"
    except ProcessLookupError:
        return f"pid {pid} not found"
    except PermissionError:
        return f"permission denied killing {pid}"
