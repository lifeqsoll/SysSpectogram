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


def _dns_egress_targets() -> list[tuple[str, str, tuple[int, ...]]]:
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
        out.append(("ip6" if addr.version == 6 else "ip", canon, (53,)))
    if out:
        return out
    # systemd-resolved stub (127.0.0.53) does not forward if upstream is dropped.
    return _resolvectl_upstreams()


def _strip_resolver_port(token: str) -> tuple[str, int | None]:
    """Drop ``:port`` from an IPv4 token, or ``[v6]:port``. IPv6 colons stay."""
    if token.startswith("[") and "]" in token:
        host, rest = token[1:].split("]", 1)
        port = None
        if rest.startswith(":") and rest[1:].isascii() and rest[1:].isdigit():
            port = int(rest[1:])
        return host, port
    if token.count(":") == 1:
        host, maybe = token.rsplit(":", 1)
        if maybe.isascii() and maybe.isdigit():
            try:
                ip_address(host)
            except ValueError:
                return token, None
            return host, int(maybe)
    return token, None


def _parse_resolvectl_dns(text: str) -> list[tuple[str, str, tuple[int, ...]]]:
    """Upstreams from ``resolvectl dns`` text: ``(family, address, ports)``.

    A ``#name`` suffix is DNS-over-TLS and adds port 853. IPv6 is kept whole.
    """
    payloads: list[str] = []
    for line in text.splitlines():
        if "): " in line:
            payloads.append(line.split("): ", 1)[1])
        elif line.startswith("Global:"):
            payloads.append(line.split(":", 1)[1])
    out: list[tuple[str, str, tuple[int, ...]]] = []
    seen: set[str] = set()
    for payload in payloads:
        for token in payload.replace(",", " ").split():
            dot = "#" in token
            body = token.split("#", 1)[0].split("%", 1)[0]
            host, explicit = _strip_resolver_port(body)
            try:
                addr = ip_address(host)
            except ValueError:
                continue
            if addr.is_loopback or str(addr) in _STUB_DNS:
                continue
            canon = str(addr)
            if canon in seen:
                continue
            seen.add(canon)
            ports = {53}
            if explicit is not None and 1 <= explicit <= 65535:
                ports.add(explicit)
            if dot:
                ports.add(853)
            ordered = tuple(sorted(ports))
            out.append(("ip6" if addr.version == 6 else "ip", canon, ordered))
    return out


def _resolvectl_upstreams() -> list[tuple[str, str, tuple[int, ...]]]:
    """Non-loopback DNS addresses from ``resolvectl dns`` (may be empty)."""
    try:
        proc = subprocess.run(
            ["resolvectl", "dns"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return _parse_resolvectl_dns(text)


def _parse_ssh_port(raw: object) -> int:
    if isinstance(raw, bool) or isinstance(raw, float):
        raise ValueError(f"ssh.port must be an integer, got {raw!r}")
    if isinstance(raw, int):
        port = raw
    elif isinstance(raw, str) and raw.isascii() and raw.isdigit():
        port = int(raw)
    else:
        raise ValueError(f"ssh.port must be an integer, got {raw!r}")
    if port < 1 or port > 65535:
        raise ValueError(f"ssh.port {port} is out of range")
    return port


def policy_from_config(config: dict | None) -> tuple[int, list[str] | None]:
    """SSH port and optional HTTPS egress list from an already loaded config.

    ``None`` for the egress list means the built-in Telegram ranges.
    An empty list means no TCP/443 egress.

    A string (not a list), a bad CIDR, or ``ssh.port: true`` raises ValueError.
    """
    ssh_port = 22
    egress: list[str] | None = None
    if not isinstance(config, dict):
        return ssh_port, egress
    ssh = config.get("ssh") or {}
    if isinstance(ssh, dict) and "port" in ssh and ssh.get("port") is not None:
        ssh_port = _parse_ssh_port(ssh.get("port"))
    kirk = config.get("kirk") or {}
    if isinstance(kirk, dict) and "egress_allow_cidrs" in kirk and kirk.get("egress_allow_cidrs") is not None:
        raw_e = kirk.get("egress_allow_cidrs")
        if not isinstance(raw_e, list):
            raise ValueError(
                "kirk.egress_allow_cidrs must be a list of CIDRs, "
                f"got {type(raw_e).__name__}: {raw_e!r}"
            )
        from sysspectogram.net_ip import nft_cidr_family

        egress = []
        for item in raw_e:
            try:
                _fam, canon = nft_cidr_family(str(item))
            except ValueError as exc:
                raise ValueError(f"kirk.egress_allow_cidrs has invalid CIDR {item!r}") from exc
            egress.append(canon)
    return ssh_port, egress


def _strict_port(port: object) -> int:
    """Integer port 0..65535. Reject bool, floats, and non-ASCII digits."""
    if isinstance(port, bool) or isinstance(port, float):
        raise ValueError(f"invalid port {port!r}")
    if isinstance(port, str):
        if not port.isascii() or not port.isdigit():
            raise ValueError(f"invalid port {port!r}")
        return int(port)
    if isinstance(port, int):
        return port
    raise ValueError(f"invalid port {port!r}")


def _comment_handle(listing: str, comment: str) -> str | None:
    needle = f'"{comment}"'
    for line in listing.splitlines():
        if needle not in line and comment not in line:
            continue
        match = re.search(r"handle\s+(\d+)", line)
        if match:
            return match.group(1)
    return None


def _synrl_drop_spec(listing: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(handle, rate, burst)`` for an existing synrl drop rule."""
    for line in listing.splitlines():
        if "sysspectogram:synrl:drop" not in line:
            continue
        handle_m = re.search(r"handle\s+(\d+)", line)
        rate_m = re.search(r"rate over\s+(\S+)", line)
        burst_m = re.search(r"burst\s+(\d+)", line)
        return (
            handle_m.group(1) if handle_m else None,
            rate_m.group(1) if rate_m else None,
            burst_m.group(1) if burst_m else None,
        )
    return None, None, None


def _cidr_targets(cidrs: list[str]) -> list[tuple[str, str]]:
    from sysspectogram.net_ip import nft_cidr_family

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
        ssh_port: int = 22,
        https_egress_cidrs: list[str] | None = None,
        allow_private_bans: bool = False,
    ) -> None:
        self.table = table
        self.chain = chain
        self.bans: dict[str, BanRecord] = {}
        self.never_ban_cidrs: list[str] = list(never_ban_cidrs or [])
        self.max_ban_ttl_sec = float(max_ban_ttl_sec)
        try:
            self.ssh_port = int(ssh_port)
        except (TypeError, ValueError):
            self.ssh_port = 22
        # None → built-in Telegram ranges. [] → no TCP/443 egress.
        self.https_egress_cidrs = (
            None if https_egress_cidrs is None else [str(c) for c in https_egress_cidrs]
        )
        self.allow_private_bans = bool(allow_private_bans)
        self._kirk_expires: float | None = None
        self._ensure_table()

    def _https_targets(self) -> list[tuple[str, str]]:
        cidrs = (
            list(DEFAULT_TELEGRAM_EGRESS_CIDRS)
            if self.https_egress_cidrs is None
            else list(self.https_egress_cidrs)
        )
        return _cidr_targets(cidrs)

    def is_never_ban(self, ip: str) -> bool:
        try:
            from sysspectogram.net_ip import unwrap_mapped_ip

            addr = unwrap_mapped_ip(ip_address(str(ip).strip()))
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
            family, ip = nft_saddr_family(ip, allow_private=self.allow_private_bans)
        except ValueError as exc:
            return f"refuse ban: {exc}"
        if self.is_never_ban(ip):
            return f"never_ban skip {ip}"
        force = bool(getattr(self, "_force_ban", False))
        if not force:
            from sysspectogram.response.protect import is_protected

            extra = list(DEFAULT_TELEGRAM_EGRESS_CIDRS)
            if self.https_egress_cidrs:
                extra.extend(self.https_egress_cidrs)
            reason = is_protected(
                ip,
                never_ban_cidrs=self.never_ban_cidrs,
                allow_private_bans=self.allow_private_bans,
                extra_cidrs=extra,
            )
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
                return HelperBanBackend(
                    never_ban_cidrs=self.never_ban_cidrs,
                    allow_private_bans=self.allow_private_bans,
                ).ban_ip(ip, ttl_sec=ttl, dry_run=False)
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
        added: list[str] = []
        listing = self._input_chain_text()
        est = "sysspectogram:lockdown:est"
        if est not in listing:
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
                    self._nft_comment(est),
                ]
            )
            if code_est != 0:
                self._drop_comments(added)
                return f"lockdown established rule failed: {out_est.strip()}"
            added.append(est)
        syn = "sysspectogram:lockdown:syn"
        syn_handle = _comment_handle(listing, syn) if syn in listing else None
        if syn in listing and not syn_handle:
            self._drop_comments(added)
            return "lockdown failed: syn drop has no handle; refusing to append allow after it"
        for fam, canon in families:
            allow_c = f"sysspectogram:lockdown:allow:{canon}"
            if allow_c in listing or allow_c in added:
                continue
            expr = [fam, "saddr", canon, "accept"]
            if syn_handle:
                argv = [
                    "nft",
                    "insert",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "position",
                    syn_handle,
                    *expr,
                    "comment",
                    self._nft_comment(allow_c),
                ]
            else:
                argv = [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    *expr,
                    "comment",
                    self._nft_comment(allow_c),
                ]
            code, out = self._run(argv)
            if code != 0:
                self._drop_comments(added)
                return f"lockdown allow failed for {canon}: {out.strip()}"
            added.append(allow_c)
        self._ensure_synrl_allows(families)
        if syn not in listing:
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
                    self._nft_comment(syn),
                ]
            )
            if code != 0:
                self._drop_comments(added)
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
        added: list[str] = []
        listing = self._input_chain_text()
        drop_c = "sysspectogram:synrl:drop"
        drop_handle = _comment_handle(listing, drop_c) if drop_c in listing else None
        if drop_c in listing and not drop_handle:
            return (
                "syn_rate_limit unchanged: drop rule has no handle "
                "(installed rate was not updated)"
            )
        for cidr in allows:
            try:
                from sysspectogram.net_ip import nft_cidr_family

                fam, canon = nft_cidr_family(cidr)
            except ValueError:
                return f"syn_rate_limit refused: invalid cidr {cidr!r}"
            allow_c = f"sysspectogram:synrl:allow:{canon}"
            if allow_c in listing:
                continue
            expr = [fam, "saddr", canon, "accept"]
            if drop_handle:
                argv = [
                    "nft",
                    "insert",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "position",
                    drop_handle,
                    *expr,
                    "comment",
                    self._nft_comment(allow_c),
                ]
            else:
                argv = [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    *expr,
                    "comment",
                    self._nft_comment(allow_c),
                ]
            code_a, out_a = self._run(argv)
            if code_a != 0:
                self._drop_comments(added)
                return f"syn_rate_limit allow failed for {canon}: {out_a.strip()}"
            added.append(allow_c)
        want_rate = str(rate)
        want_burst = str(int(burst))
        if drop_c not in listing:
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
                    want_rate,
                    "burst",
                    want_burst,
                    "packets",
                    "drop",
                    "comment",
                    self._nft_comment(drop_c),
                ]
            )
            if code != 0:
                self._drop_comments(added)
                return f"syn_rate_limit failed: {out.strip()}"
            return f"syn_rate_limit active rate over {want_rate} burst={want_burst} allow={allows or '-'}"
        handle, installed_rate, installed_burst = _synrl_drop_spec(listing)
        if installed_rate == want_rate and installed_burst == want_burst:
            return (
                f"syn_rate_limit active rate over {installed_rate} "
                f"burst={installed_burst} allow={allows or '-'}"
            )
        if not handle:
            return (
                "syn_rate_limit unchanged: drop rule has no handle "
                f"(installed rate over {installed_rate or '?'} burst={installed_burst or '?'})"
            )
        code, out = self._run(
            [
                "nft",
                "replace",
                "rule",
                "inet",
                "sysspectogram",
                "input",
                "handle",
                handle,
                "tcp",
                *_TCP_FLAGS_SYN_ONLY,
                "limit",
                "rate",
                "over",
                want_rate,
                "burst",
                want_burst,
                "packets",
                "drop",
                "comment",
                self._nft_comment(drop_c),
            ]
        )
        if code != 0:
            return (
                "syn_rate_limit unchanged: "
                f"installed rate over {installed_rate or '?'} burst={installed_burst or '?'} "
                f"(replace failed: {out.strip()})"
            )
        return f"syn_rate_limit active rate over {want_rate} burst={want_burst} allow={allows or '-'}"

    def _ensure_synrl_allows(self, families: list[tuple[str, str]]) -> None:
        """If syn-rate-limit is active, insert matching allows before the drop."""
        listing = self._input_chain_text()
        drop_c = "sysspectogram:synrl:drop"
        if drop_c not in listing:
            return
        drop_handle = _comment_handle(listing, drop_c)
        if not drop_handle:
            return
        for fam, canon in families:
            allow_c = f"sysspectogram:synrl:allow:{canon}"
            if allow_c in listing:
                continue
            self._run(
                [
                    "nft",
                    "insert",
                    "rule",
                    "inet",
                    "sysspectogram",
                    "input",
                    "position",
                    drop_handle,
                    fam,
                    "saddr",
                    canon,
                    "accept",
                    "comment",
                    self._nft_comment(allow_c),
                ]
            )

    def shield_port(
        self,
        port: int,
        ttl_sec: float = 3600.0,
        dry_run: bool = False,
        *,
        force: bool = False,
        ssh_port: int | None = None,
    ) -> str:
        try:
            port_i = _strict_port(port)
        except ValueError:
            return f"shield refused: invalid port {port!r}"
        if port_i < 1 or port_i > 65535:
            return f"shield refused: port out of range {port_i}"
        try:
            ssh = self.ssh_port if ssh_port is None else _strict_port(ssh_port)
        except ValueError:
            return f"shield refused: invalid ssh port {ssh_port!r}"
        if not force and port_i in {int(ssh), 22}:
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
        ssh_port: int | None = None,
    ) -> str:
        """L2: drop new inbound TCP to app ports (default 80/443); SSH untouched.

        Keeps established/related. Does not cut egress (unlike kirk isolate).
        """
        raw_ports = list(ports or [80, 443])
        cleaned: list[int] = []
        try:
            ssh = self.ssh_port if ssh_port is None else _strict_port(ssh_port)
        except ValueError:
            return f"quarantine refused: invalid ssh port {ssh_port!r}"
        for p in raw_ports:
            try:
                pi = _strict_port(p)
            except ValueError:
                return f"quarantine refused: invalid port {p!r}"
            if pi < 1 or pi > 65535:
                return f"quarantine refused: port out of range {pi}"
            if pi == int(ssh) or pi == 22:
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

    def _input_chain_text(self) -> str:
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        return out if code == 0 else ""

    def _drop_comments(self, comments: list[str]) -> None:
        """Delete only rules whose comment is in ``comments`` (this call's adds)."""
        if not comments:
            return
        code, out = self._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        if code != 0:
            return
        for line in out.splitlines():
            if not any(c in line for c in comments):
                continue
            m = re.search(r"handle\s+(\d+)", line)
            if not m:
                continue
            self._run(
                ["nft", "delete", "rule", "inet", "sysspectogram", "input", "handle", m.group(1)]
            )

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
        ``/etc/resolv.conf`` (loopback stub via ``oif lo``; upstreams from
        ``resolvectl dns`` when the file is stub-only). A stub with no upstream
        does not resolve public names. TCP/443 only to
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
        # DoT resolvers (#name) also get 853. A 2-tuple target is plain port 53.
        for spec in _dns_egress_targets():
            fam, addr = spec[0], spec[1]
            ports = spec[2] if len(spec) > 2 else (53,)
            for port in ports:
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
                            str(port),
                            "accept",
                        ]
                    )
                    if code != 0:
                        return _rollback(f"dns allow {addr}:{port}: {out.strip()}")
        # HTTPS only to Telegram publish ranges (or kirk.egress_allow_cidrs override).
        for fam, cidr in self._https_targets():
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
