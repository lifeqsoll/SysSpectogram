from __future__ import annotations

import math
import os
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
# nft 1.1.x requires a flag *list* after `/`; bare `syn / syn` is a syntax error.
# Resulting match: tcp flags & (fin | syn | rst | ack) == syn
_TCP_FLAGS_SYN_ONLY = ("flags", "syn", "/", "fin,syn,rst,ack")

# Snapshot of https://core.telegram.org/resources/cidr.txt — not "any :443".
# ``kirk.egress_allow_cidrs`` in config replaces this list (empty = no HTTPS egress).
DEFAULT_TELEGRAM_EGRESS_CIDRS = (
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "91.105.192.0/23",
    "185.76.151.0/24",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/48",
    "2a0a:f280::/32",
)
_STUB_DNS = frozenset({"127.0.0.1", "127.0.0.53", "::1"})


def _dns_egress_targets() -> list[tuple[str, str]]:
    """Non-loopback nameservers from /etc/resolv.conf as nft (family, address)."""
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        raw = parts[1].split("%", 1)[0]
        try:
            addr = ip_address(raw)
        except ValueError:
            continue
        if addr.is_loopback or str(addr) in _STUB_DNS:
            continue
        canon = str(addr)
        if canon in seen:
            continue
        seen.add(canon)
        out.append(("ip6" if addr.version == 6 else "ip", canon))
    return out


def _kirk_https_targets() -> list[tuple[str, str]]:
    """Telegram (or configured) CIDRs allowed to tcp/443 during isolate."""
    from sysspectogram.net_ip import nft_cidr_family

    cidrs: list[str] = list(DEFAULT_TELEGRAM_EGRESS_CIDRS)
    try:
        from sysspectogram.config import load_config

        kirk = load_config().get("kirk") or {}
        if "egress_allow_cidrs" in kirk and kirk.get("egress_allow_cidrs") is not None:
            cidrs = [str(c) for c in (kirk.get("egress_allow_cidrs") or [])]
    except Exception:
        pass
    out: list[tuple[str, str]] = []
    for cidr in cidrs:
        try:
            out.append(nft_cidr_family(cidr))
        except ValueError:
            continue
    return out

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


@dataclass
class BanResult:
    """Structured ban outcome (F-05). ``str(result)`` stays CLI/Telegram compatible."""

    ok: bool
    ip: str
    backend: str
    detail: str
    skipped: bool = False

    def __str__(self) -> str:
        return self.detail


def classify_ban_message(msg: str, *, ip: str = "") -> BanResult:
    """Parse legacy ban_ip string into BanResult."""
    text = str(msg or "")
    low = text.lower()
    if text.startswith("banned") or text.startswith("dry-run ban"):
        backend = "nft"
        if "backend=helper" in text:
            backend = "helper"
        elif "backend=iptables" in text or "backend=ip6tables" in text:
            backend = "iptables"
        elif "backend=dry-run" in text or text.startswith("dry-run"):
            backend = "dry-run"
        return BanResult(ok=True, ip=ip, backend=backend, detail=text, skipped=False)
    if "never_ban" in low or "protected skip" in low or text.startswith("protected"):
        return BanResult(ok=False, ip=ip, backend="none", detail=text, skipped=True)
    if "skip" in low and "refuse" not in low:
        return BanResult(ok=False, ip=ip, backend="none", detail=text, skipped=True)
    return BanResult(ok=False, ip=ip, backend="none", detail=text, skipped=False)


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
        """Clamp a positive finite TTL. ``None`` → max. Raises ``ValueError`` for junk."""
        if ttl_sec is None:
            return self.max_ban_ttl_sec
        try:
            ttl = float(ttl_sec)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid ttl: {ttl_sec!r}") from exc
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError(f"ttl must be a positive finite number, got {ttl_sec!r}")
        return max(DEFAULT_MIN_BAN_TTL_SEC, min(ttl, self.max_ban_ttl_sec))

    def _run(self, cmd: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)

    @staticmethod
    def _nft_comment(text: str) -> str:
        """Quote an nft comment so colons are not parsed as syntax (argv token)."""
        cleaned = str(text or "").replace('"', "").replace("\n", " ").replace("\r", " ").strip()
        return f'"{cleaned}"'

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
        force = bool(getattr(self, "_force_ban", False))
        if not force:
            from sysspectogram.response.protect import is_protected

            reason = is_protected(ip, never_ban_cidrs=self.never_ban_cidrs)
            if reason:
                return f"protected skip {ip} ({reason})"
        try:
            ttl = self._clamp_ttl(ttl_sec)
        except ValueError as exc:
            return f"refuse ban: {exc}"
        expires = time.time() + ttl
        comment = f"sysspectogram:{ip}:{int(expires)}"
        if dry_run:
            self.bans[ip] = BanRecord(ip, time.time(), expires, comment, None, "dry-run")
            return f"dry-run ban {ip} ttl={ttl}"
        # Friend path (F-02): non-root guard bans via helper group auth, not CAP_NET_ADMIN.
        if os.geteuid() != 0:
            from sysspectogram.response.helper_ban import HelperBanBackend, helper_available

            if helper_available():
                return HelperBanBackend(never_ban_cidrs=self.never_ban_cidrs).ban_ip(
                    ip, ttl_sec=ttl, dry_run=False
                )
            return "nft failed: no privileges (install helper and join group sysspectogram)"
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
        if os.geteuid() != 0:
            from sysspectogram.response.helper_ban import HelperBanBackend, helper_available

            if helper_available():
                return HelperBanBackend(never_ban_cidrs=self.never_ban_cidrs).unban_ip(
                    ip, dry_run=False
                )
            return "nft unban failed: no privileges (install helper)"
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

    def list_nft_set_ips(self) -> list[str]:
        """Parse live ``nft list set`` for ban4/ban6 (same token scan as the helper)."""
        out = self.list_bans_result()
        return list(out.get("ips") or []) if out.get("ok") and out.get("source") == "nft" else []

    def list_bans(self) -> list[BanRecord]:
        now = time.time()
        expired = [ip for ip, b in self.bans.items() if b.expires and b.expires <= now]
        for ip in expired:
            self.unban_ip(ip)
        self.expire_kirk_isolate()
        self.expire_shield_ports()
        return list(self.bans.values())

    def reconcile_kirk_from_disk(self) -> str | None:
        """Load or release ss_kirk from this HOME's deadline. Call only from guard/web start."""
        return self._load_kirk_deadline()

    @staticmethod
    def _kirk_state_path() -> Path:
        from sysspectogram.config import state_root

        return state_root() / "state" / "kirk_isolate.json"

    def _write_kirk_deadline(self, expires: float, allow_cidrs: list[str]) -> None:
        path = self._kirk_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        payload = {
            "expires_at": float(expires),
            "allow_cidrs": list(allow_cidrs),
            "updated_at": time.time(),
        }
        text = __import__("json").dumps(payload, indent=2) + "\n"
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def _clear_kirk_deadline(self) -> None:
        path = self._kirk_state_path()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        self._kirk_expires = None

    def _load_kirk_deadline(self) -> str | None:
        """Restore TTL from disk; release ss_kirk if expired or deadline missing.

        Only call this from guard/web startup (``reconcile_kirk_from_disk``).
        A stray ``NftBackend()`` (for example ``bans list`` under another HOME)
        must not delete an active isolate table.
        """
        path = self._kirk_state_path()
        table_present = False
        if shutil.which("nft"):
            code, _ = self._run(["nft", "list", "table", "inet", "ss_kirk"])
            table_present = code == 0
        expires: float | None = None
        if path.is_file():
            try:
                data = __import__("json").loads(path.read_text(encoding="utf-8"))
                expires = float(data.get("expires_at") or 0) or None
            except (OSError, ValueError, TypeError):
                expires = None
        if table_present and (expires is None or time.time() >= float(expires)):
            return self.kirk_release(dry_run=False)
        if expires is not None and time.time() < float(expires):
            self._kirk_expires = float(expires)
            return None
        if expires is not None:
            self._clear_kirk_deadline()
        return None

    def list_bans_result(self) -> dict:
        """CLI-facing list: live nft sets when root; memory only for in-process non-root."""
        if os.geteuid() == 0:
            if not shutil.which("nft"):
                return {
                    "ok": False,
                    "ips": [],
                    "error": "nft not found",
                    "hint": "install nftables (provides the nft binary)",
                }
            ips: list[str] = []
            seen: set[str] = set()
            listed = 0
            for set_name in ("ban4", "ban6"):
                code, out = self._run(["nft", "list", "set", "inet", "sysspectogram", set_name])
                if code != 0:
                    continue
                listed += 1
                for token in (out or "").split():
                    tok = token.strip().strip(",{}")
                    if not tok:
                        continue
                    try:
                        addr = str(ip_address(tok))
                    except ValueError:
                        continue
                    if addr not in seen:
                        seen.add(addr)
                        ips.append(addr)
            if listed == 0:
                return {
                    "ok": False,
                    "ips": [],
                    "error": "nft list set failed",
                    "hint": "table inet sysspectogram missing or unreadable; install helper / run a ban once",
                }
            return {"ok": True, "ips": ips, "source": "nft"}
        # Non-root CLI uses HelperBanBackend / NoneBanBackend via select_ban_backend.
        # Memory source is for the long-lived guard process that recorded bans in-process.
        mem = [b.ip for b in self.list_bans()]
        return {"ok": True, "ips": mem, "source": "memory"}
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
        code_est, out_est = self._run(
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
                self._nft_comment("sysspectogram:lockdown:est"),
            ]
        )
        if code_est != 0:
            self.release_lockdown()
            return f"lockdown established rule failed: {out_est.strip()}"
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
                    self._nft_comment(f"sysspectogram:lockdown:allow:{canon}"),
                ]
            )
            if code != 0:
                self.release_lockdown()
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
                *_TCP_FLAGS_SYN_ONLY,
                "drop",
                "comment",
                self._nft_comment("sysspectogram:lockdown:syn"),
            ]
        )
        if code != 0:
            self.release_lockdown()
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
            code_a, out_a = self._run(
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
                    self._nft_comment(f"sysspectogram:synrl:allow:{canon}"),
                ]
            )
            if code_a != 0:
                self.release_lockdown()
                return f"syn_rate_limit allow failed for {canon}: {out_a.strip()}"
        code, out = self._run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "tcp",
                *_TCP_FLAGS_SYN_ONLY,
                "limit",
                "rate",
                "over",
                str(rate),
                "burst",
                str(int(burst)),
                "packets",
                "drop",
                "comment",
                self._nft_comment("sysspectogram:synrl:drop"),
            ]
        )
        if code != 0:
            self.release_lockdown()
            return f"syn_rate_limit failed: {out.strip()}"
        return f"syn_rate_limit active rate over {rate} burst={burst} allow={allows or '-'}"

    def shield_port(
        self,
        port: int,
        ttl_sec: float = 3600.0,
        dry_run: bool = False,
        *,
        force: bool = False,
        ssh_port: int = 22,
    ) -> str:
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            return f"shield refused: invalid port {port!r}"
        if port_i < 1 or port_i > 65535:
            return f"shield refused: port out of range {port_i}"
        if not force and port_i == int(ssh_port):
            return f"shield refused: port {port_i} is SSH (pass force=True to override)"
        try:
            ttl = self._clamp_ttl(ttl_sec)
        except ValueError as exc:
            return f"shield refused: {exc}"
        if dry_run:
            return f"dry-run shield port {port_i} for {ttl}s (ct state new)"
        if shutil.which("nft"):
            self._ensure_chain()
            # Accept never_ban before drop so admin SSH path is not cut if they force 22.
            for cidr in self.never_ban_cidrs:
                try:
                    from sysspectogram.net_ip import nft_cidr_family

                    fam, canon = nft_cidr_family(str(cidr))
                except ValueError:
                    continue
                marker = f"sysspectogram:portallow:{port_i}:{canon}"
                listed, listing = self._run(
                    ["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"]
                )
                if listed == 0 and marker in listing:
                    continue
                code_a, out_a = self._run(
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
                        "tcp",
                        "dport",
                        str(port_i),
                        "accept",
                        "comment",
                        self._nft_comment(marker),
                    ]
                )
                if code_a != 0:
                    return f"shield failed: portallow {canon}: {out_a.strip()}"
            comment = f"sysspectogram:port:{port_i}:{int(time.time() + ttl)}"
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "ct",
                    "state",
                    "new",
                    "tcp",
                    "dport",
                    str(port_i),
                    "drop",
                    "comment",
                    self._nft_comment(comment),
                ]
            )
            if code != 0:
                return f"shield failed: {out.strip()}"
            return f"shielded port {port_i} ttl={ttl}"
        return "nft required for shield_port"

    def quarantine_ports(
        self,
        ports: list[int] | None = None,
        *,
        dry_run: bool = False,
        ttl_sec: float = 3600.0,
        ssh_port: int = 22,
    ) -> str:
        """L2: drop new inbound TCP to app ports (default 80/443); SSH untouched.

        Keeps established/related. Does not cut egress (unlike kirk isolate).
        """
        raw_ports = list(ports or [80, 443])
        cleaned: list[int] = []
        for p in raw_ports:
            try:
                pi = int(p)
            except (TypeError, ValueError):
                return f"quarantine refused: invalid port {p!r}"
            if pi < 1 or pi > 65535:
                return f"quarantine refused: port out of range {pi}"
            if pi == int(ssh_port) or pi == 22:
                return f"quarantine refused: port {pi} (SSH) — leave SSH untouched"
            cleaned.append(pi)
        ports = cleaned
        if not ports:
            return "quarantine refused: no ports"
        if dry_run:
            return f"dry-run quarantine ports={ports} ttl={ttl_sec}"
        if not shutil.which("nft"):
            return "nft required for quarantine"
        self._ensure_chain()
        # established first (idempotent-ish — duplicate accepts are ok)
        code_est, out_est = self._run(
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
                self._nft_comment("sysspectogram:quarantine:est"),
            ]
        )
        if code_est != 0:
            return f"quarantine established rule failed: {out_est.strip()}"
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
                    self._nft_comment(comment),
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

        TTL is persisted to ``state/kirk_isolate.json`` so a guard restart still
        releases the table. Output allows DNS only to resolvers from
        ``/etc/resolv.conf`` (loopback stub via ``oif lo``) and TCP/443 only to
        ``kirk.egress_allow_cidrs`` (default: Telegram publish ranges). Release
        via SSH on an allow-CIDR or when the TTL expires.

        All CIDRs are validated *before* any nft mutation so a typo cannot leave
        a policy-drop table with no allow rules.
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
        try:
            ttl = self._clamp_ttl(ttl_sec)
        except ValueError as exc:
            return f"kirk_isolate refused: {exc}"
        if dry_run:
            return f"dry-run kirk_isolate allow={allow_cidrs} ttl={ttl}"
        if not shutil.which("nft"):
            return "nft required for kirk_isolate"

        def _rollback(reason: str) -> str:
            self._run(["nft", "delete", "table", "inet", "ss_kirk"])
            self._clear_kirk_deadline()
            return f"kirk_isolate failed: {reason} (table removed)"

        code, out = self._run(["nft", "add", "table", "inet", "ss_kirk"])
        if code != 0 and "exists" not in out.lower():
            return f"kirk_isolate failed: create table: {out.strip()}"
        self._run(["nft", "flush", "table", "inet", "ss_kirk"])
        for chain_argv in (
            [
                "nft",
                "add",
                "chain",
                "inet",
                "ss_kirk",
                "input",
                "{ type filter hook input priority -10 ; policy drop ; }",
            ],
            [
                "nft",
                "add",
                "chain",
                "inet",
                "ss_kirk",
                "output",
                "{ type filter hook output priority -10 ; policy drop ; }",
            ],
        ):
            code, out = self._run(chain_argv)
            if code != 0 and "exists" not in out.lower():
                return _rollback(f"chain: {out.strip()}")
        # always allow loopback + established
        for chain in ("input", "output"):
            code, out = self._run(
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
            if code != 0:
                return _rollback(f"established {chain}: {out.strip()}")
        for argv in (
            ["nft", "add", "rule", "inet", "ss_kirk", "input", "iif", "lo", "accept"],
            ["nft", "add", "rule", "inet", "ss_kirk", "output", "oif", "lo", "accept"],
        ):
            code, out = self._run(argv)
            if code != 0:
                return _rollback(f"base allow: {out.strip()}")
        # DNS only toward configured resolvers (stub 127.0.0.53 stays on oif lo).
        for fam, addr in _dns_egress_targets():
            for proto in ("udp", "tcp"):
                code, out = self._run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        "ss_kirk",
                        "output",
                        fam,
                        "daddr",
                        addr,
                        proto,
                        "dport",
                        "53",
                        "accept",
                    ]
                )
                if code != 0:
                    return _rollback(f"dns allow {addr}: {out.strip()}")
        # HTTPS only to Telegram publish ranges (or kirk.egress_allow_cidrs override).
        for fam, cidr in _kirk_https_targets():
            code, out = self._run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "ss_kirk",
                    "output",
                    fam,
                    "daddr",
                    cidr,
                    "tcp",
                    "dport",
                    "443",
                    "accept",
                ]
            )
            if code != 0:
                return _rollback(f"https allow {cidr}: {out.strip()}")
        for fam, canon in families:
            code, out = self._run(
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
            if code != 0:
                return _rollback(f"ssh allow {canon}: {out.strip()}")
            code, out = self._run(
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
            if code != 0:
                return _rollback(f"ssh reply {canon}: {out.strip()}")
        expires = time.time() + ttl
        self._kirk_expires = expires
        try:
            self._write_kirk_deadline(expires, allow_cidrs)
        except OSError as exc:
            return _rollback(f"persist deadline: {exc}")
        return f"kirk_isolate active allow={allow_cidrs} ttl={ttl}"

    def kirk_release(self, dry_run: bool = False) -> str:
        if dry_run:
            self._kirk_expires = None
            return "dry-run kirk_release"
        if not shutil.which("nft"):
            self._clear_kirk_deadline()
            return "nft required"
        code, out = self._run(["nft", "delete", "table", "inet", "ss_kirk"])
        self._clear_kirk_deadline()
        if code != 0 and "No such file" not in out and "does not exist" not in out:
            return f"kirk_release failed: {out.strip()}"
        return "kirk_release ok"

    def expire_kirk_isolate(self, dry_run: bool = False) -> str | None:
        """Release ss_kirk when this process's in-memory TTL elapsed.

        Does not read another HOME's deadline or delete a table it did not arm.
        Startup recovery is ``reconcile_kirk_from_disk``.
        """
        if self._kirk_expires is None:
            return None
        if time.time() < self._kirk_expires:
            return None
        return self.kirk_release(dry_run=dry_run)

    def expire_shield_ports(self, dry_run: bool = False) -> str | None:
        """Remove ``sysspectogram:port:*`` rules whose comment deadline has passed."""
        if dry_run or not shutil.which("nft"):
            return None
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        if code != 0:
            return None
        now = time.time()
        expired_ports: set[str] = set()
        handles: list[str] = []
        for line in out.splitlines():
            m_exp = re.search(r"sysspectogram:port:(\d+):(\d+)", line)
            if m_exp and now >= float(m_exp.group(2)):
                expired_ports.add(m_exp.group(1))
                m_h = re.search(r"handle\s+(\d+)", line)
                if m_h:
                    handles.append(m_h.group(1))
        if expired_ports:
            for line in out.splitlines():
                m_allow = re.search(r"sysspectogram:portallow:(\d+):", line)
                if not m_allow or m_allow.group(1) not in expired_ports:
                    continue
                m_h = re.search(r"handle\s+(\d+)", line)
                if m_h:
                    handles.append(m_h.group(1))
        removed = 0
        for handle in handles:
            hc, _ = self._run(
                ["nft", "delete", "rule", "inet", "sysspectogram", "input", "handle", handle]
            )
            if hc == 0:
                removed += 1
        return f"expire_shield removed={removed}" if removed else None


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
