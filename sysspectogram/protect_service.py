"""User systemd unit so protect survives Control Center exit (friend path)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root

UNIT_NAME = "sysspectogram-protect.service"


def _home() -> Path:
    return state_root()


def _python() -> Path:
    venv = _home() / ".venv" / "bin" / "python"
    if venv.is_file():
        return venv
    return Path(shutil.which("python3") or "python3")


def _unit_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "systemd" / "user"


def unit_path() -> Path:
    return _unit_dir() / UNIT_NAME


def _unit_body() -> str:
    home = _home().resolve()
    py = _python().resolve()
    # No --dry-run: response.mode from overlay controls auto-ban; friends expect real protect.
    return f"""[Unit]
Description=SysSpectogram protect (user)
After=network.target
ConditionPathExists={home}

[Service]
Type=simple
WorkingDirectory={home}
Environment=SYSSPECTOGRAM_HOME={home}
ExecStart={py} -m sysspectogram guard --telegram
Restart=on-failure
RestartSec=5
StandardOutput=append:{home}/state/guard-service.log
StandardError=append:{home}/state/guard-service.log

[Install]
WantedBy=default.target
"""


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def status() -> dict[str, Any]:
    path = unit_path()
    installed = path.is_file()
    active = False
    enabled = False
    detail = ""
    if shutil.which("systemctl"):
        st = _systemctl("is-active", UNIT_NAME)
        active = st.returncode == 0 and st.stdout.strip() == "active"
        en = _systemctl("is-enabled", UNIT_NAME)
        enabled = en.returncode == 0 and en.stdout.strip() == "enabled"
        detail = (st.stdout or st.stderr or "").strip()
    else:
        detail = "systemctl not found"
    out: dict[str, Any] = {
        "ok": True,
        "unit": UNIT_NAME,
        "unit_path": str(path),
        "home": str(_home()),
        "python": str(_python()),
        "installed": installed,
        "enabled": enabled,
        "active": active,
        "detail": detail,
    }
    linger = _linger_hint()
    if linger:
        out["hint"] = linger
        out["linger"] = False
    else:
        out["linger"] = True
    return out


def install_and_enable() -> dict[str, Any]:
    if not shutil.which("systemctl"):
        return {"ok": False, "error": "systemctl not available"}
    home = _home()
    (home / "state").mkdir(parents=True, exist_ok=True)
    udir = _unit_dir()
    udir.mkdir(parents=True, exist_ok=True)
    path = unit_path()
    path.write_text(_unit_body(), encoding="utf-8")
    _systemctl("daemon-reload")
    en = _systemctl("enable", "--now", UNIT_NAME)
    if en.returncode != 0:
        return {
            "ok": False,
            "error": (en.stderr or en.stdout or "enable failed").strip(),
            "unit_path": str(path),
            "hint": "On a VPS, also run: loginctl enable-linger $USER",
        }
    linger = _linger_hint()
    out = {"ok": True, **status()}
    if linger:
        out["hint"] = linger
    return out


def _linger_hint() -> str | None:
    """User units die on logout unless linger is enabled (typical headless VPS)."""
    try:
        import getpass

        user = getpass.getuser()
        r = subprocess.run(
            ["loginctl", "show-user", user, "-p", "Linger"],
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode == 0 and "Linger=yes" in (r.stdout or ""):
            return None
    except OSError:
        pass
    return "On SSH/VPS run once: loginctl enable-linger $USER (else protect stops on logout)"


def disable_and_stop() -> dict[str, Any]:
    if not shutil.which("systemctl"):
        return {"ok": False, "error": "systemctl not available"}
    _systemctl("disable", "--now", UNIT_NAME)
    # Leave unit file so re-enable is one click; optional unlink:
    # unit_path().unlink(missing_ok=True)
    return {"ok": True, **status()}


def start() -> dict[str, Any]:
    if not unit_path().is_file():
        return install_and_enable()
    r = _systemctl("start", UNIT_NAME)
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout or "start failed").strip()}
    return {"ok": True, **status()}


def stop() -> dict[str, Any]:
    r = _systemctl("stop", UNIT_NAME)
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout or "stop failed").strip()}
    return {"ok": True, **status()}


def restart() -> dict[str, Any]:
    if not unit_path().is_file():
        return install_and_enable()
    r = _systemctl("restart", UNIT_NAME)
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout or "restart failed").strip()}
    return {"ok": True, **status()}
