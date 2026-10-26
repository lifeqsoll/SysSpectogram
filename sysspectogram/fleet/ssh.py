"""SSH helpers for fleet fan-out from the admin PC."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sysspectogram.fleet.store import FleetHost


@dataclass
class SshResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int

    def json(self) -> dict[str, Any] | None:
        text = (self.stdout or "").strip()
        if not text:
            return None
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


@dataclass(frozen=True)
class SshDestination:
    """Parsed ssh target: user@host with optional port (never embed port in hostname)."""

    user: str | None
    host: str
    port: int | None

    def ssh_argv_dest(self) -> str:
        """Destination token for ``ssh -- <dest>`` (no port; use ``-p`` separately)."""
        if self.user:
            return f"{self.user}@{self.host}"
        return self.host

    def known_hosts_name(self) -> str:
        """Host name token for a known_hosts line (brackets + port when needed)."""
        if self.port is not None:
            return f"[{self.host}]:{self.port}"
        if ":" in self.host:
            return f"[{self.host}]"
        return self.host


def parse_ssh_destination(ssh_dest: str) -> SshDestination | None:
    """Parse ``user@host``, ``user@host:port``, ``user@[ipv6]:port``.

    Rejects empty / leading-``-`` destinations (option injection).
    """
    dest = (ssh_dest or "").strip()
    if not dest or dest.startswith("-"):
        return None
    user: str | None = None
    hostport = dest
    if "@" in dest:
        user, hostport = dest.split("@", 1)
        user = user.strip() or None
        hostport = hostport.strip()
        if user and user.startswith("-"):
            return None
    if not hostport or hostport.startswith("-"):
        return None
    host: str
    port: int | None = None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            return None
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if rest:
            if not (rest.startswith(":") and rest[1:].isdigit()):
                return None
            port = int(rest[1:])
    elif hostport.count(":") == 1:
        left, right = hostport.rsplit(":", 1)
        if right.isdigit() and left and not left.startswith("-"):
            host, port = left, int(right)
        else:
            host = hostport
    else:
        # bare hostname, or bare IPv6 (multiple colons)
        host = hostport
    if not host or host.startswith("-"):
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    return SshDestination(user=user, host=host, port=port)


def ssh_binary() -> str:
    for name in ("ssh", "ssh.exe"):
        found = shutil.which(name)
        if found:
            return found
    return "ssh"


def allow_tofu() -> bool:
    return os.environ.get("FLEET_SSH_TOFU", "").strip() in ("1", "true", "yes")


def require_host_pin(host: FleetHost, *, mutating: bool) -> str | None:
    """Return error string if host must be pinned for this op."""
    if (host.host_key_line or "").strip():
        return None
    if not mutating:
        return None
    if allow_tofu():
        return None
    return (
        f"host {host.id}: host_key_line required for mutating fleet ops "
        "(fleet pin-host, or FLEET_SSH_TOFU=1)"
    )


def _ssh_base_args(
    host: FleetHost,
    *,
    identity: str | None = None,
    parsed: SshDestination | None = None,
) -> tuple[list[str], Path | None]:
    """Build ssh argv; if host_key_line is set, pin via a temp known_hosts file."""
    cmd = [
        ssh_binary(),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
    ]
    if parsed and parsed.port is not None:
        cmd.extend(["-p", str(parsed.port)])
    known: Path | None = None
    line = (host.host_key_line or "").strip()
    if line:
        parts = line.split()
        if len(parts) >= 3 and parts[0] not in (
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ):
            kh_line = line
        else:
            dest = parsed or parse_ssh_destination(host.ssh)
            name = dest.known_hosts_name() if dest else (host.ssh or "unknown")
            kh_line = f"{name} {line}"
        fd, path_s = tempfile.mkstemp(prefix="ss-fleet-kh-", suffix=".known")
        os.close(fd)
        known = Path(path_s)
        known.write_text(kh_line + "\n", encoding="utf-8")
        try:
            known.chmod(0o600)
        except OSError:
            pass
        cmd.extend(
            [
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=" + str(known),
                "-o",
                "GlobalKnownHostsFile=/dev/null",
            ]
        )
    else:
        cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
    if identity:
        cmd.extend(["-i", identity])
    return cmd, known


def ssh_run(
    host: FleetHost,
    remote_command: str,
    *,
    timeout: float = 60.0,
    identity: str | None = None,
    stdin_data: str | None = None,
) -> SshResult:
    if not host.ssh:
        return SshResult(False, "", "ssh target empty", 2)
    dest_raw = (host.ssh or "").strip()
    if not dest_raw or dest_raw.startswith("-"):
        return SshResult(False, "", "invalid ssh destination (must not be empty or start with -)", 2)
    parsed = parse_ssh_destination(dest_raw)
    if parsed is None:
        return SshResult(False, "", "invalid ssh destination", 2)
    cmd, known = _ssh_base_args(host, identity=identity, parsed=parsed)
    cmd.append("--")
    cmd.append(parsed.ssh_argv_dest())
    cmd.append(remote_command)
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return SshResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return SshResult(False, "", "ssh timeout", 124)
    except OSError as exc:
        return SshResult(False, "", str(exc), 1)
    finally:
        if known is not None:
            try:
                known.unlink(missing_ok=True)
            except OSError:
                pass


def remote_python(host: FleetHost) -> str:
    home = (host.home_path or "").rstrip("/") or "."
    return f"{shlex.quote(home)}/.venv/bin/python"


def remote_control(
    host: FleetHost,
    payload: dict[str, Any],
    *,
    timeout: float = 60.0,
    identity: str | None = None,
    mutating: bool = False,
) -> dict[str, Any]:
    """Run control.sock request on the remote host via SSH.

    Payload (including device_token) is sent on SSH stdin as JSON so the token
    never appears in remote process argv.
    """
    pin_err = require_host_pin(host, mutating=mutating)
    if pin_err:
        return {"ok": False, "error": pin_err, "host_id": host.id}

    home = (host.home_path or "").rstrip("/") or "."
    py = remote_python(host)
    body = dict(payload)
    if host.device_token and "device_token" not in body:
        body["device_token"] = host.device_token
    # Remote snippet reads JSON from stdin — no secrets in -c string.
    remote = (
        f"cd {shlex.quote(home)} && {py} -c "
        + shlex.quote(
            "import json,sys;"
            "from sysspectogram.control_socket import request;"
            "from sysspectogram.config import state_root;"
            "p=json.load(sys.stdin);"
            "sock=state_root()/'state'/'control.sock';"
            "print(json.dumps(request(sock,p),ensure_ascii=False))"
        )
    )
    t0 = time.perf_counter()
    r = ssh_run(
        host,
        remote,
        timeout=timeout,
        identity=identity,
        stdin_data=json.dumps(body, separators=(",", ":")),
    )
    latency_ms = (time.perf_counter() - t0) * 1000.0
    data = r.json()
    if data is None:
        return {
            "ok": False,
            "error": r.stderr.strip() or r.stdout.strip() or f"ssh rc={r.returncode}",
            "host_id": host.id,
            "latency_ms": round(latency_ms, 1),
        }
    data.setdefault("host_id", host.id)
    data.setdefault("latency_ms", round(latency_ms, 1))
    return data


def remote_cat_unlock_code(host: FleetHost, *, identity: str | None = None) -> str | None:
    pin_err = require_host_pin(host, mutating=True)
    if pin_err:
        return None
    home = (host.home_path or "").rstrip("/") or "."
    r = ssh_run(
        host,
        f"cat {shlex.quote(home)}/state/unlock.code 2>/dev/null",
        timeout=30.0,
        identity=identity,
    )
    code = (r.stdout or "").strip()
    return code or None
