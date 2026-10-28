from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path

# Kernel set timeout upper bound for auto-bans (D-1 / F-01). Forever bans forbidden.
DEFAULT_MAX_BAN_TTL_SEC = 7 * 24 * 3600
DEFAULT_MIN_BAN_TTL_SEC = 60

_NFT_TABLE_SCRIPT = """\
table inet sysspectogram {
  set ban4 {
    type ipv4_addr
    flags timeout
  }
  set ban6 {
    type ipv6_addr
    flags timeout
  }
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr @ban4 drop
    ip6 saddr @ban6 drop
  }
}
"""


@dataclass
class BanRecord:
    ip: str
    created: float
    expires: float | None
    comment: str
    handle: int | None = None
    backend: str = "memory"


class NftBackend:
    """nft/iptables ban manager using named sets with kernel timeouts (fail2ban-style)."""

    def __init__(
        self,
        table: str = "inet",
        chain: str = "sysspectogram",
        *,
        never_ban_cidrs: list[str] | None = None,
        max_ban_ttl_sec: float = DEFAULT_MAX_BAN_TTL_SEC,
    ) -> None:
        self.table = table
        self.chain = chain
        self.bans: dict[str, BanRecord] = {}
        self.never_ban_cidrs: list[str] = list(never_ban_cidrs or [])
        self.max_ban_ttl_sec = float(max_ban_ttl_sec)
        self._kirk_expires: float | None = None
        self._ensure_table()

    def is_never_ban(self, ip: str) -> bool:
        try:
            from sysspectogram.net_ip import parse_ban_ip

            addr = ip_address(parse_ban_ip(ip))
        except ValueError:
            # Fail-closed for never-ban checks: invalid IPs are not "protected",
            # but ban_ip must also reject them before touching nft.
            return False
        for cidr in self.never_ban_cidrs:
            try:
                if addr in ip_network(str(cidr).strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _clamp_ttl(self, ttl_sec: float | None) -> float:
        if ttl_sec is None:
            return self.max_ban_ttl_sec
        ttl = float(ttl_sec)
        if ttl <= 0:
            return self.max_ban_ttl_sec
        return max(DEFAULT_MIN_BAN_TTL_SEC, min(ttl, self.max_ban_ttl_sec))

    def _run(self, cmd: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)

    def _nft_stdin(self, text: str) -> tuple[int, str]:
        """Apply nft ruleset text via argv ``nft -f -`` (no shell)."""
        if not shutil.which("nft"):
            return 1, "nft missing"
        try:
            proc = subprocess.run(
                ["nft", "-f", "-"],
                input=text,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)

    def _ensure_table(self) -> None:
        """Idempotent table/sets/chain. Create-or-ignore via create + flush-safe adds."""
        if not shutil.which("nft"):
            return
        # Prefer create; ignore "File exists". Then ensure sets/chain pieces.
        self._run(["nft", "create", "table", "inet", "sysspectogram"])
        self._run(
            [
                "nft",
                "create",
                "set",
                "inet",
                "sysspectogram",
                "ban4",
                "{",
                "type",
                "ipv4_addr",
                ";",
                "flags",
                "timeout",
                ";",
                "}",
            ]
        )
        self._run(
            [
                "nft",
                "create",
                "set",
                "inet",
                "sysspectogram",
                "ban6",
                "{",
                "type",
                "ipv6_addr",
                ";",
                "flags",
                "timeout",
                ";",
                "}",
            ]
        )
        self._run(
            [
                "nft",
                "create",
                "chain",
                "inet",
                "sysspectogram",
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "-10",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ]
        )
        # Drop rules referencing sets (idempotent: ignore duplicates by checking list).
        code, out = self._run(["nft", "list", "chain", "inet", "sysspectogram", "input"])
        if code == 0 and "@ban4" not in out:
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "ip",
                    "saddr",
                    "@ban4",
                    "drop",
                ]
            )
        if code == 0 and "@ban6" not in out:
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "ip6",
                    "saddr",
                    "@ban6",
                    "drop",
                ]
            )
        # Fallback if create pieces failed oddly: full script once.
        code_t, _ = self._run(["nft", "list", "table", "inet", "sysspectogram"])
        if code_t != 0:
            self._nft_stdin(_NFT_TABLE_SCRIPT)

    # Back-compat alias used by lockdown/quarantine helpers.
    def _ensure_chain(self) -> None:
        self._ensure_table()

    def _set_name(self, family: str) -> str:
        return "ban6" if family == "ip6" else "ban4"

    def ban_ip(self, ip: str, ttl_sec: float | None = 3600.0, dry_run: bool = False) -> str:
        from sysspectogram.net_ip import nft_saddr_family

        try:
            family, ip = nft_saddr_family(ip)
        except ValueError as exc:
            return f"refuse ban: {exc}"
        if self.is_never_ban(ip):
            return f"never_ban skip {ip}"
        ttl = self._clamp_ttl(ttl_sec)
        expires = time.time() + ttl
        comment = f"sysspectogram:{ip}:{int(expires)}"
        if dry_run:
            self.bans[ip] = BanRecord(ip, time.time(), expires, comment, None, "dry-run")
            return f"dry-run ban {ip} ttl={ttl}"
        backend = "memory"
        if shutil.which("nft"):
            self._ensure_table()
            set_name = self._set_name(family)
            # Named set + kernel timeout (fail2ban-style). No comment argv (F-01).
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "element",
                    "inet",
                    "sysspectogram",
                    set_name,
                    "{",
                    ip,
                    "timeout",
                    f"{int(ttl)}s",
                    "}",
                ]
            )
            if code != 0:
                # Element may already exist — try delete+add once.
                self._run(
                    [
                        "nft",
                        "delete",
                        "element",
                        "inet",
                        "sysspectogram",
                        set_name,
                        "{",
                        ip,
                        "}",
                    ]
                )
                code, out = self._run(
                    [
                        "nft",
                        "add",
                        "element",
                        "inet",
                        "sysspectogram",
                        set_name,
                        "{",
                        ip,
                        "timeout",
                        f"{int(ttl)}s",
                        "}",
                    ]
                )
            if code != 0:
                return f"nft failed: {out.strip()}"
            backend = "nft"
        elif shutil.which("iptables") or shutil.which("ip6tables"):
            ipt = "ip6tables" if family == "ip6" and shutil.which("ip6tables") else "iptables"
            if family == "ip6" and ipt != "ip6tables":
                return "no ip6tables available for IPv6 ban"
            # Replace existing DROP for this source if present.
            self._run([ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"])
            code, out = self._run(
                [
                    ipt,
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
                return f"{ipt} failed: {out.strip()}"
            backend = ipt
        else:
            return "no nft/iptables available"
        self.bans[ip] = BanRecord(ip, time.time(), expires, comment, None, backend)
        return f"banned {ip} ttl={ttl} backend={backend}"

    def unban_ip(self, ip: str, dry_run: bool = False) -> str:
        from sysspectogram.net_ip import nft_saddr_family

        try:
            family, ip = nft_saddr_family(ip)
        except ValueError as exc:
            return f"refuse unban: {exc}"
        self.bans.pop(ip, None)
        if dry_run:
            return f"dry-run unban {ip}"
        if shutil.which("nft"):
            set_name = self._set_name(family)
            code, out = self._run(
                [
                    "nft",
                    "delete",
                    "element",
                    "inet",
                    "sysspectogram",
                    set_name,
                    "{",
                    ip,
                    "}",
                ]
            )
            if code != 0:
                # Already gone is ok for idempotent unban.
                if "No such file" in out or "does not exist" in out or "not found" in out.lower():
                    return f"unbanned {ip} nft (absent)"
                return f"nft unban failed: {out.strip()}"
            return f"unbanned {ip} nft set={set_name}"
        ipt = "ip6tables" if family == "ip6" and shutil.which("ip6tables") else "iptables"
        if shutil.which(ipt):
            for _ in range(8):
                code, _ = self._run([ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"])
                if code != 0:
                    break
            return f"unban attempted for {ip} ({ipt})"
        return f"unban recorded {ip}"

    def list_bans(self) -> list[BanRecord]:
        now = time.time()
        expired = [ip for ip, b in self.bans.items() if b.expires and b.expires <= now]
        for ip in expired:
            self.unban_ip(ip)
        self.expire_kirk_isolate()
        return list(self.bans.values())

    def apply_lockdown(
        self,
        dry_run: bool = False,
        *,
        allow_cidrs: list[str] | None = None,
    ) -> str:
        """Drop new inbound SYN; keep established + explicit allow_cidrs (never-ban / SSH).

        This is a **host soft-mitigation** under scan/flood noise — not anti-DDoS / CDN.
        Always pass admin SSH CIDRs or you can lock yourself out of new sessions.
        """
        from sysspectogram.net_ip import nft_cidr_family, validate_allow_ssh_cidrs

        raw_allows = [str(c).strip() for c in (allow_cidrs or self.never_ban_cidrs or []) if str(c).strip()]
        # Refuse empty / invalid allow before any nft mutation.
        if not raw_allows:
            return (
                "lockdown refused: allow_cidrs/never_ban empty "
                "(would drop new SSH SYN from your admin IP)"
            )
        try:
            allows = validate_allow_ssh_cidrs(raw_allows)
            families = [nft_cidr_family(c) for c in allows]
        except ValueError as exc:
            return f"lockdown refused: {exc}"
        if dry_run:
            return (
                "dry-run lockdown: established+allow_cidrs accept, then SYN drop "
                f"allow={allows or '-'}"
            )
        if not shutil.which("nft"):
            return "nft required for lockdown"
        self._ensure_chain()
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
        for fam, canon in families:
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    fam,
                    "saddr",
                    canon,
                    "accept",
                    "comment",
                    f"sysspectogram:lockdown:allow:{canon}",
                ]
            )
            if code != 0:
                return f"lockdown allow failed for {canon}: {out.strip()}"
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
        return f"lockdown nft rules applied (SYN drop; allow={allows}; established kept)"

    def apply_syn_rate_limit(
        self,
        *,
        rate: str = "25/second",
        burst: int = 50,
        dry_run: bool = False,
        allow_cidrs: list[str] | None = None,
    ) -> str:
        """Soft per-host SYN rate limit (nft). Not a DDoS scrubber."""
        allows = [str(c).strip() for c in (allow_cidrs or self.never_ban_cidrs or []) if str(c).strip()]
        if dry_run:
            return f"dry-run syn_rate_limit rate={rate} burst={burst} allow={allows or '-'}"
        if not shutil.which("nft"):
            return "nft required for syn_rate_limit"
        self._ensure_chain()
        for cidr in allows:
            try:
                from sysspectogram.net_ip import nft_cidr_family

                fam, canon = nft_cidr_family(cidr)
            except ValueError:
                return f"syn_rate_limit refused: invalid cidr {cidr!r}"
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    fam,
                    "saddr",
                    canon,
                    "accept",
                    "comment",
                    f"sysspectogram:synrl:allow:{canon}",
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
                "limit",
                "rate",
                "over",
                str(rate),
                "burst",
                str(int(burst)),
                "packets",
                "drop",
                "comment",
                "sysspectogram:synrl:drop",
            ]
        )
        if code != 0:
            return f"syn_rate_limit failed: {out.strip()}"
        return f"syn_rate_limit active rate over {rate} burst={burst} allow={allows or '-'}"

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

    def quarantine_ports(
        self,
        ports: list[int] | None = None,
        *,
        dry_run: bool = False,
        ttl_sec: float = 3600.0,
    ) -> str:
        """L2: drop new inbound TCP to app ports (default 80/443); SSH untouched.

        Keeps established/related. Does not cut egress (unlike kirk isolate).
        """
        ports = [int(p) for p in (ports or [80, 443]) if int(p) > 0]
        if not ports:
            return "quarantine refused: no ports"
        if dry_run:
            return f"dry-run quarantine ports={ports} ttl={ttl_sec}"
        if not shutil.which("nft"):
            return "nft required for quarantine"
        self._ensure_chain()
        # established first (idempotent-ish — duplicate accepts are ok)
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
                "sysspectogram:quarantine:est",
            ]
        )
        applied: list[int] = []
        exp = int(time.time() + float(ttl_sec))
        for port in ports:
            comment = f"sysspectogram:quarantine:{port}:{exp}"
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
                return f"quarantine failed on :{port}: {out.strip()}"
            applied.append(port)
        return f"quarantine active ports={applied} ttl={ttl_sec}s (SSH not blocked)"

    def release_quarantine(self, dry_run: bool = False) -> str:
        """Remove rules tagged sysspectogram:quarantine:*."""
        if dry_run:
            return "dry-run release_quarantine"
        if not shutil.which("nft"):
            return "nft required"
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        if code != 0:
            return f"release_quarantine list failed: {out.strip()}"
        removed = 0
        for line in out.splitlines():
            if "sysspectogram:quarantine:" not in line:
                continue
            m = re.search(r"handle\s+(\d+)", line)
            if not m:
                continue
            hc, _ = self._run(
                ["nft", "delete", "rule", "inet", "sysspectogram", "input", "handle", m.group(1)]
            )
            if hc == 0:
                removed += 1
        return f"release_quarantine removed={removed}"

    def release_lockdown(self, dry_run: bool = False) -> str:
        """Remove rules tagged sysspectogram:lockdown:*."""
        if dry_run:
            return "dry-run release_lockdown"
        if not shutil.which("nft"):
            return "nft required"
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        if code != 0:
            return f"release_lockdown list failed: {out.strip()}"
        removed = 0
        for line in out.splitlines():
            if "sysspectogram:lockdown:" not in line and "sysspectogram:synrl:" not in line:
                continue
            m = re.search(r"handle\s+(\d+)", line)
            if not m:
                continue
            hc, _ = self._run(
                ["nft", "delete", "rule", "inet", "sysspectogram", "input", "handle", m.group(1)]
            )
            if hc == 0:
                removed += 1
        return f"release_lockdown removed={removed}"

    def kirk_isolate(
        self,
        *,
        allow_cidrs: list[str] | None = None,
        dry_run: bool = False,
        ttl_sec: float = 3600.0,
    ) -> str:
        """Drop most traffic except allowlisted SSH sources (table inet ss_kirk).

        TTL is tracked in-process; call ``expire_kirk_isolate`` / ``list_bans`` to release.

        All CIDRs are validated *before* any nft mutation so a typo cannot leave
        a policy-drop table with no allow rules (and no way out via Telegram).
        """
        from sysspectogram.net_ip import nft_cidr_family, validate_allow_ssh_cidrs

        raw = list(allow_cidrs or [])
        if not raw:
            return "kirk_isolate refused: allow_ssh_cidrs empty (would lock you out)"
        try:
            allow_cidrs = validate_allow_ssh_cidrs(raw)
        except ValueError as exc:
            return f"kirk_isolate refused: {exc}"
        families: list[tuple[str, str]] = []
        for cidr in allow_cidrs:
            try:
                families.append(nft_cidr_family(cidr))
            except ValueError as exc:
                return f"kirk_isolate refused: invalid cidr {cidr!r} ({exc})"
        if dry_run:
            return f"dry-run kirk_isolate allow={allow_cidrs} ttl={ttl_sec}"
        if not shutil.which("nft"):
            return "nft required for kirk_isolate"
        self._run(["nft", "add", "table", "inet", "ss_kirk"])
        self._run(["nft", "flush", "table", "inet", "ss_kirk"])
        self._run(
            [
                "nft",
                "add",
                "chain",
                "inet",
                "ss_kirk",
                "input",
                "{ type filter hook input priority -10 ; policy drop ; }",
            ]
        )
        self._run(
            [
                "nft",
                "add",
                "chain",
                "inet",
                "ss_kirk",
                "output",
                "{ type filter hook output priority -10 ; policy drop ; }",
            ]
        )
        # always allow loopback + established
        for chain in ("input", "output"):
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "ss_kirk",
                    chain,
                    "ct",
                    "state",
                    "established,related",
                    "accept",
                ]
            )
        self._run(["nft", "add", "rule", "inet", "ss_kirk", "input", "iif", "lo", "accept"])
        self._run(["nft", "add", "rule", "inet", "ss_kirk", "output", "oif", "lo", "accept"])
        for fam, canon in families:
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "ss_kirk",
                    "input",
                    fam,
                    "saddr",
                    canon,
                    "tcp",
                    "dport",
                    "22",
                    "accept",
                ]
            )
            self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "ss_kirk",
                    "output",
                    fam,
                    "daddr",
                    canon,
                    "ct",
                    "state",
                    "established,related",
                    "accept",
                ]
            )
        ttl = max(60.0, float(ttl_sec)) if ttl_sec else 3600.0
        self._kirk_expires = time.time() + ttl
        return f"kirk_isolate active allow={allow_cidrs} ttl={ttl}"

    def kirk_release(self, dry_run: bool = False) -> str:
        if dry_run:
            self._kirk_expires = None
            return "dry-run kirk_release"
        if not shutil.which("nft"):
            return "nft required"
        code, out = self._run(["nft", "delete", "table", "inet", "ss_kirk"])
        self._kirk_expires = None
        if code != 0 and "No such file" not in out and "does not exist" not in out:
            return f"kirk_release failed: {out.strip()}"
        return "kirk_release ok"

    def expire_kirk_isolate(self, dry_run: bool = False) -> str | None:
        """Release ss_kirk when TTL elapsed. Returns message if released, else None."""
        if self._kirk_expires is None:
            return None
        if time.time() < self._kirk_expires:
            return None
        return self.kirk_release(dry_run=dry_run)


def read_proc_comm(pid: int) -> str | None:
    try:
        return Path(f"/proc/{int(pid)}/comm").read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None


def kill_pid(pid: int, dry_run: bool = False, *, expect_comm: str | None = None) -> str:
    if pid <= 1:
        return "refusing to kill pid<=1"
    if expect_comm:
        live = read_proc_comm(pid)
        if live is None:
            return f"kill skipped: pid {pid} gone"
        if live != expect_comm:
            return f"kill skipped: pid {pid} is {live!r}, expected {expect_comm!r}"
    if dry_run:
        return f"dry-run kill {pid}" + (f" ({expect_comm})" if expect_comm else "")
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
