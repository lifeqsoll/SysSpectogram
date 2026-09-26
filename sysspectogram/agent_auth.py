"""HMAC-SHA256 auth for agent -> guard critical alerts."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Any

CRITICAL_RULES = frozenset(
    {
        "agent_kirk_module_hide",
        "agent_kirk_pid_hide",
        "agent_kirk_symbol_drift",
        "agent_kirk_ima_mismatch",
        "agent_kirk_guard_down",
        "agent_kirk_agent_down",
        "agent_kirk_clean_shutdown",
        "agent_unexpected_root",
    }
)


def ensure_secret(path: Path) -> str:
    path = Path(path)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if raw:
            return raw
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_hex(32)
    path.write_text(raw + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return raw


def load_secret(path: Path | None = None, env: str = "SYSSPECTOGRAM_AGENT_HMAC") -> str | None:
    env_v = (os.environ.get(env) or "").strip()
    if env_v:
        return env_v
    if path and Path(path).exists():
        raw = Path(path).read_text(encoding="utf-8").strip()
        return raw or None
    return None


def canonical_payload(obj: dict[str, Any]) -> str:
    rule = str(obj.get("rule_id") or "")
    sev = str(obj.get("severity") or "")
    ts = float(obj.get("ts") or 0.0)
    pid = obj.get("pid")
    pid_s = "" if pid is None else str(int(pid))
    path = str(obj.get("path") or "")[:256]
    msg = str(obj.get("message") or "")[:256]
    return f"v1|{rule}|{sev}|{ts:.3f}|{pid_s}|{path}|{msg}"


def sign(secret: str, obj: dict[str, Any]) -> str:
    dig = hmac.new(
        secret.encode("utf-8"),
        canonical_payload(obj).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return dig


def verify(secret: str, obj: dict[str, Any], *, max_skew_sec: float = 120.0) -> bool:
    got = str(obj.get("hmac") or "").strip().lower()
    if not got or len(got) != 64:
        return False
    try:
        ts = float(obj.get("ts") or 0.0)
    except (TypeError, ValueError):
        return False
    import time

    if abs(time.time() - ts) > max_skew_sec:
        return False
    expect = sign(secret, obj)
    return hmac.compare_digest(expect, got)


def needs_hmac(rule_id: str) -> bool:
    return str(rule_id) in CRITICAL_RULES
