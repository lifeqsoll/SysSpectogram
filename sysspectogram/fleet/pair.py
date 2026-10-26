"""Pair a remote VPS into fleet.json (SSH → home pair-remote / pair-complete → add)."""

from __future__ import annotations

import json
import shlex
from typing import Any

from sysspectogram.fleet.ssh import remote_python, ssh_run
from sysspectogram.fleet.store import FleetHost, FleetStore


def pair_start(
    *,
    ssh: str,
    home_path: str,
    label: str = "device",
    identity: str | None = None,
    host_key_line: str = "",
) -> dict[str, Any]:
    """SSH to host and run `home pair-remote`. Returns pair_code (show on admin UI)."""
    host = FleetHost(
        id="_pair",
        label=label or "device",
        ssh=ssh,
        home_path=home_path,
        host_key_line=host_key_line,
    )
    # pair-remote is not a control.sock mutate — allow without pin for first contact
    home = (home_path or "").rstrip("/") or "."
    py = remote_python(host)
    lab = shlex.quote((label or "device").strip() or "device")
    remote = f"cd {shlex.quote(home)} && {py} -m sysspectogram home pair-remote --label {lab}"
    r = ssh_run(host, remote, identity=identity, timeout=45.0)
    data = r.json()
    if not data:
        return {
            "ok": False,
            "error": r.stderr.strip() or r.stdout.strip() or f"ssh rc={r.returncode}",
        }
    data.setdefault("ssh", ssh)
    data.setdefault("home_path", home_path)
    data.setdefault("label", label)
    return data


def pair_finish(
    store: FleetStore,
    *,
    ssh: str,
    home_path: str,
    code: str,
    host_id: str,
    label: str = "",
    role: str = "worker",
    identity: str | None = None,
    host_key_line: str = "",
) -> dict[str, Any]:
    """SSH pair-complete → upsert fleet host with device_token (shown once in result)."""
    hid = (host_id or "").strip()
    if not hid:
        return {"ok": False, "error": "host_id required"}
    if not (code or "").strip():
        return {"ok": False, "error": "pair code required"}
    host = FleetHost(
        id=hid,
        label=(label or hid).strip() or hid,
        ssh=ssh,
        home_path=home_path,
        host_key_line=host_key_line,
        role=role or "worker",
    )
    from sysspectogram.fleet.ssh import require_host_pin

    pin_err = require_host_pin(host, mutating=True)
    if pin_err:
        return {
            "ok": False,
            "error": pin_err + " — run fleet keyscan then pass --host-key-line before pair-finish",
        }
    home = (home_path or "").rstrip("/") or "."
    py = remote_python(host)
    lab = shlex.quote((label or hid).strip() or hid)
    remote = (
        f"cd {shlex.quote(home)} && {py} -m sysspectogram home pair-complete "
        f"{shlex.quote(code.strip())} --label {lab}"
    )
    r = ssh_run(host, remote, identity=identity, timeout=45.0)
    data = r.json() or {}
    if not data.get("ok"):
        return {
            "ok": False,
            "error": data.get("error") or r.stderr.strip() or r.stdout.strip() or "pair-complete failed",
            "remote": data,
        }
    token = str(data.get("device_token") or "")
    device_id = str(data.get("device_id") or "")
    if not token:
        return {"ok": False, "error": "pair-complete returned no device_token", "remote": data}
    host.device_token = token
    host.device_id = device_id
    store.upsert_host(host)
    out = {
        "ok": True,
        "host_id": hid,
        "device_id": device_id,
        "device_token": token,
        "hint": "Token stored in fleet.json (mode 0600). UI will mask it.",
        "pinned": bool((host_key_line or "").strip()),
    }
    if not out["pinned"]:
        out["warn"] = "set host_key_line via fleet pin-host before mutating ops"
    return out


def parse_ssh_host_port(ssh_dest: str) -> tuple[str, int | None] | None:
    """Extract host + optional port from user@host[:port] / [ipv6] forms.

    Rejects destinations that look like SSH option injection (leading ``-``).
    """
    dest = (ssh_dest or "").strip()
    if not dest or dest.startswith("-"):
        return None
    hostport = dest.split("@", 1)[-1].strip()
    if not hostport or hostport.startswith("-"):
        return None
    if hostport.startswith("["):
        # [2001:db8::1] or [2001:db8::1]:2222
        end = hostport.find("]")
        if end < 0:
            return None
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if not rest:
            return (host, None)
        if rest.startswith(":") and rest[1:].isdigit():
            return (host, int(rest[1:]))
        return None
    if hostport.count(":") == 1:
        host, port_s = hostport.rsplit(":", 1)
        if port_s.isdigit() and host and not host.startswith("-"):
            return (host, int(port_s))
    if ":" in hostport and hostport.count(":") > 1:
        # bare IPv6 without brackets
        return (hostport, None)
    return (hostport, None)


def suggest_keyscan(ssh_dest: str) -> dict[str, Any]:
    """Best-effort local ssh-keyscan hint (admin runs manually if needed)."""
    import shutil
    import subprocess

    parsed = parse_ssh_host_port(ssh_dest)
    if not parsed:
        return {"ok": False, "error": "invalid ssh destination", "host": None}
    host_part, port = parsed
    keyscan = shutil.which("ssh-keyscan") or shutil.which("ssh-keyscan.exe")
    if not keyscan:
        return {"ok": False, "error": "ssh-keyscan not found", "host": host_part}
    # ssh-keyscan has no ``--`` on all platforms; never pass a leading-``-`` host.
    if host_part.startswith("-"):
        return {"ok": False, "error": "invalid host (must not start with -)", "host": host_part}
    cmd = [keyscan, "-T", "5", "-t", "ed25519,rsa"]
    if port is not None:
        cmd.extend(["-p", str(port)])
    # Prefer bracketed form for IPv6 so keyscan does not mis-split on ':'.
    scan_host = host_part
    if ":" in host_part and not host_part.startswith("["):
        scan_host = f"[{host_part}]"
    cmd.append(scan_host)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc), "host": host_part, "port": port}
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        return {
            "ok": False,
            "error": proc.stderr.strip() or "no keys",
            "host": host_part,
            "port": port,
        }
    return {
        "ok": True,
        "host": host_part,
        "port": port,
        "host_key_line": lines[0].strip(),
        "all": lines,
    }
