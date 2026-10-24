"""SSH helpers for fleet fan-out from the admin PC."""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
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


def _ssh_base_args(host: FleetHost, *, identity: str | None = None) -> tuple[list[str], Path | None]:
    """Build ssh argv; if host_key_line is set, pin via a temp known_hosts file."""
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
    ]
    known: Path | None = None
    line = (host.host_key_line or "").strip()
    if line:
        parts = line.split()
        # Full known_hosts line already has hostname as first token.
        if len(parts) >= 3 and parts[0] not in (
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ):
            kh_line = line
        else:
            dest = host.ssh
            host_part = dest.split("@", 1)[-1].split(":", 1)[0]
            kh_line = f"{host_part} {line}"
        fd, path_s = tempfile.mkstemp(prefix="ss-fleet-kh-", suffix=".known")
        import os

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
                f"UserKnownHostsFile={known}",
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
) -> SshResult:
    if not host.ssh:
        return SshResult(False, "", "ssh target empty", 2)
    cmd, known = _ssh_base_args(host, identity=identity)
    cmd.append(host.ssh)
    cmd.append(remote_command)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
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
) -> dict[str, Any]:
    """Run control.sock request on the remote host via SSH."""
    home = (host.home_path or "").rstrip("/") or "."
    py = remote_python(host)
    body = dict(payload)
    if host.device_token and "device_token" not in body:
        body["device_token"] = host.device_token
    payload_lit = json.dumps(body, separators=(",", ":"))
    remote = (
        f"cd {shlex.quote(home)} && {py} -c "
        + shlex.quote(
            "import json; "
            "from sysspectogram.control_socket import request; "
            "from sysspectogram.config import state_root; "
            f"p=json.loads({payload_lit!r}); "
            "sock=state_root()/'state'/'control.sock'; "
            "print(json.dumps(request(sock,p),ensure_ascii=False))"
        )
    )
    r = ssh_run(host, remote, timeout=timeout, identity=identity)
    data = r.json()
    if data is None:
        return {
            "ok": False,
            "error": r.stderr.strip() or r.stdout.strip() or f"ssh rc={r.returncode}",
            "host_id": host.id,
        }
    data.setdefault("host_id", host.id)
    return data


def remote_cat_unlock_code(host: FleetHost, *, identity: str | None = None) -> str | None:
    home = (host.home_path or "").rstrip("/") or "."
    r = ssh_run(
        host,
        f"cat {shlex.quote(home)}/state/unlock.code 2>/dev/null",
        timeout=30.0,
        identity=identity,
    )
    code = (r.stdout or "").strip()
    return code or None
