"""Warmup / readiness checklist for enabling shield on a host."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root


def warmup_checklist(root: Path | None = None) -> dict[str, Any]:
    """Local (this VPS) checklist — also usable over SSH by running the CLI remotely."""
    root = root or state_root()
    state = root / "state"
    checks: list[dict[str, Any]] = []

    def add(cid: str, ok: bool, detail: str) -> None:
        checks.append({"id": cid, "ok": ok, "detail": detail})

    us = state / "user-settings.json"
    mode = "observe"
    never_ban = ""
    if us.is_file():
        try:
            data = json.loads(us.read_text(encoding="utf-8"))
            mode = str(data.get("response.mode") or mode)
            never_ban = str(data.get("response.never_ban_cidrs") or "")
        except (OSError, json.JSONDecodeError):
            pass
    add("never_ban", bool(str(never_ban).strip()), f"never_ban={never_ban or '(empty)'}")
    add(
        "not_isolate_by_default",
        mode not in ("isolate",),
        f"response.mode={mode}",
    )

    labels = state / "process_labels.json"
    n_labels = 0
    if labels.is_file():
        try:
            raw = json.loads(labels.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                n_labels = len(raw)
            elif isinstance(raw, dict):
                n_labels = len(raw.get("rules") or raw.get("labels") or raw)
        except (OSError, json.JSONDecodeError):
            pass
    add("feedback_labels", n_labels >= 3, f"labels≈{n_labels} (want ≥3 As normal/anomaly)")

    fb = state / "operator_feedback.json"
    add("feedback_file", fb.is_file(), "operator_feedback present" if fb.is_file() else "no feedback yet")

    unlock = state / "control.unlocked"
    add("unlocked_session", unlock.is_file(), "control.unlocked" if unlock.is_file() else "LOCKED or never unlocked")

    devices = state / "remote.devices.json"
    add("remote_paired", devices.is_file(), "remote devices file" if devices.is_file() else "no pair yet (ok for single-host)")

    ready_for_shield = all(
        c["ok"] for c in checks if c["id"] in ("never_ban", "feedback_labels")
    )
    return {
        "ok": True,
        "ready_for_shield": ready_for_shield,
        "checks": checks,
        "hint": "Enable shield only when ready_for_shield; Attack L2+ stays manual.",
    }
