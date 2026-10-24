"""Decide when to auto-kill a process from an alert (only when auto-ban/shield is on)."""

from __future__ import annotations

from typing import Any

from sysspectogram.response.actions import kill_pid, read_proc_comm

# Candidate rules for auto-kill — still gated by auto_ban_enabled.
HARD_KILL_RULES = frozenset(
    {
        "canary_hit",
        "honeypot_hit",
        "egress_denylist_hit",
    }
)

_MALWARE_MARKERS = (
    "xmrig",
    "minerd",
    "kdevtmpfsi",
    "kinsing",
    ".xmr",
    "/dev/shm/",
)


def looks_malware(comm: str | None, path: str | None) -> bool:
    blob = f"{comm or ''} {path or ''}".lower()
    return any(m in blob for m in _MALWARE_MARKERS)


def want_auto_kill(
    rule_id: str | None,
    *,
    comm: str | None = None,
    path: str | None = None,
    auto_ban_enabled: bool = False,
) -> bool:
    """Auto-kill only when the operator enabled auto-ban/shield.

    Observe / auto-ban off → never auto-kill (malware included); Kill button only.
    """
    if not auto_ban_enabled:
        return False
    rid = str(rule_id or "")
    if rid in HARD_KILL_RULES:
        return True
    if looks_malware(comm, path):
        return True
    if rid == "agent_unexpected_root":
        return True
    return False


def try_auto_kill(
    pid: int | None,
    *,
    expect_comm: str | None = None,
    dry_run: bool = False,
    reason: str = "",
) -> str | None:
    """Return kill result string, or None if skipped."""
    if pid is None or int(pid) <= 1:
        return None
    pid = int(pid)
    live = read_proc_comm(pid)
    if live is None:
        return None
    expect = expect_comm or live
    msg = kill_pid(pid, dry_run=dry_run, expect_comm=expect)
    return f"AUTO-KILL pid={pid} expect={expect} ({reason}): {msg}"


def auto_kill_from_alert(
    alert: Any,
    *,
    auto_ban_enabled: bool,
    dry_run: bool,
) -> str | None:
    rid = getattr(alert, "rule_id", None)
    pid = getattr(alert, "pid", None)
    comm = getattr(alert, "comm", None)
    path = getattr(alert, "path", None)
    if not want_auto_kill(rid, comm=comm, path=path, auto_ban_enabled=auto_ban_enabled):
        return None
    return try_auto_kill(pid, expect_comm=str(comm) if comm else None, dry_run=dry_run, reason=str(rid))
