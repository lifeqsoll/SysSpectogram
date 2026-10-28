"""Stop friend install and drop host-side nft state (data dir optional)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root
from sysspectogram.protect_service import disable_and_stop


def _drop_nft_table() -> dict[str, Any]:
    if not shutil.which("nft"):
        return {"ok": False, "detail": "nft not installed"}
    proc = subprocess.run(
        ["nft", "delete", "table", "inet", "sysspectogram"],
        capture_output=True,
        text=True,
        check=False,
    )
    err = (proc.stderr or proc.stdout or "").strip()
    if proc.returncode == 0:
        return {"ok": True, "detail": "deleted table inet sysspectogram"}
    if "No such file" in err or "does not exist" in err.lower():
        return {"ok": True, "detail": "table inet sysspectogram absent"}
    return {"ok": False, "detail": err or f"nft exit {proc.returncode}"}


def uninstall_stack(*, purge_data: bool = False) -> dict[str, Any]:
    """Disable user protect, remove nft table, optionally delete SYSSPECTOGRAM_HOME."""
    home = state_root()
    steps: list[dict[str, Any]] = []
    steps.append({"protect": disable_and_stop()})
    steps.append({"nft": _drop_nft_table()})
    unit = Path.home() / ".config/systemd/user/sysspectogram-protect.service"
    if unit.is_file():
        try:
            unit.unlink()
            steps.append({"unit": "removed sysspectogram-protect.service"})
        except OSError as exc:
            steps.append({"unit": f"could not remove unit: {exc}"})
    if purge_data and home.exists():
        try:
            shutil.rmtree(home)
            steps.append({"data": f"removed {home}"})
        except OSError as exc:
            steps.append({"data": f"could not remove {home}: {exc}"})
            return {"ok": False, "steps": steps, "home": str(home)}
    note = (
        f"Data still under {home} — delete manually if you want a clean remove."
        if not purge_data
        else None
    )
    return {"ok": True, "steps": steps, "home": str(home), "note": note}
