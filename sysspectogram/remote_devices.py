"""Paired remote Control Center devices (SSH hub ↔ this VPS).

Pairing: short-lived host-only code → long-lived device token (hash stored here).
Raw token is shown once to the admin PC and never logged.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root
from sysspectogram.console_unlock import CODE_ALPHABET, DEFAULT_CODE_LEN, ConsoleUnlock

DEVICES_NAME = "remote.devices.json"
PENDING_NAME = "remote.pair_pending.json"
TOKEN_BYTES = 32


def _devices_path(root: Path | None = None) -> Path:
    return (root or state_root()) / "state" / DEVICES_NAME


def _pending_path(root: Path | None = None) -> Path:
    return (root or state_root()) / "state" / PENDING_NAME


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_code(code: str) -> str:
    return ConsoleUnlock.normalize(code)


def _gen_pair_code(length: int = DEFAULT_CODE_LEN) -> str:
    n = len(CODE_ALPHABET)
    return "".join(CODE_ALPHABET[secrets.randbelow(n)] for _ in range(max(6, length)))


def _gen_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


@dataclass
class DeviceRecord:
    device_id: str
    label: str
    token_hash: str
    created_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "label": self.label,
            "token_hash": self.token_hash,
            "created_at": self.created_at,
        }


def list_devices(root: Path | None = None) -> list[DeviceRecord]:
    raw = _load_json(_devices_path(root), {"devices": []})
    out: list[DeviceRecord] = []
    for row in raw.get("devices") or []:
        if not isinstance(row, dict):
            continue
        out.append(
            DeviceRecord(
                device_id=str(row.get("device_id") or ""),
                label=str(row.get("label") or ""),
                token_hash=str(row.get("token_hash") or ""),
                created_at=float(row.get("created_at") or 0),
            )
        )
    return [d for d in out if d.device_id and d.token_hash]


def _save_devices(devices: list[DeviceRecord], root: Path | None = None) -> None:
    payload = {"schema": "remote.devices.v1", "devices": [d.as_dict() for d in devices]}
    _write_private(_devices_path(root), json.dumps(payload, indent=2) + "\n")


def devices_configured(root: Path | None = None) -> bool:
    return bool(list_devices(root))


def begin_pair(*, label: str = "", ttl_sec: float = 300.0, root: Path | None = None) -> dict[str, Any]:
    """Start pairing; returns pair code (show on host only)."""
    code = _gen_pair_code()
    pending = {
        "code": code,
        "label": (label or "device").strip()[:64] or "device",
        "expires_at": time.time() + float(ttl_sec),
    }
    _write_private(_pending_path(root), json.dumps(pending) + "\n")
    return {
        "ok": True,
        "pair_code": code,
        "ttl_sec": ttl_sec,
        "label": pending["label"],
        "hint": "Enter this code on the admin PC within ttl_sec. Never send it via Telegram.",
    }


def complete_pair(code: str, *, label: str | None = None, root: Path | None = None) -> dict[str, Any]:
    """Consume pair code; return raw device_token once."""
    path = _pending_path(root)
    pending = _load_json(path, None)
    if not isinstance(pending, dict) or not pending.get("code"):
        return {"ok": False, "error": "no pending pair — run home pair-remote first"}
    if time.time() > float(pending.get("expires_at") or 0):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return {"ok": False, "error": "pair code expired — run home pair-remote again"}
    got = normalize_code(code)
    want = normalize_code(str(pending["code"]))
    # compare_digest requires equal length; mistyped codes must not raise.
    if len(got) != len(want) or not secrets.compare_digest(got, want):
        return {"ok": False, "error": "bad pair code"}
    token = _gen_token()
    device_id = secrets.token_hex(8)
    lab = (label or pending.get("label") or "device").strip()[:64] or "device"
    devices = list_devices(root)
    devices.append(
        DeviceRecord(
            device_id=device_id,
            label=lab,
            token_hash=_hash_token(token),
            created_at=time.time(),
        )
    )
    _save_devices(devices, root)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return {
        "ok": True,
        "device_id": device_id,
        "label": lab,
        "device_token": token,
        "hint": "Store device_token only on the admin PC (fleet.json). It will not be shown again.",
    }


def revoke_device(device_id: str, *, root: Path | None = None) -> dict[str, Any]:
    devices = list_devices(root)
    keep = [d for d in devices if d.device_id != device_id]
    if len(keep) == len(devices):
        return {"ok": False, "error": "device not found"}
    _save_devices(keep, root)
    return {"ok": True, "revoked": device_id, "remaining": len(keep)}


def revoke_all(*, root: Path | None = None) -> dict[str, Any]:
    _save_devices([], root)
    return {"ok": True, "revoked": "all"}


def verify_token(token: str | None, *, root: Path | None = None) -> DeviceRecord | None:
    if not token or not str(token).strip():
        return None
    digest = _hash_token(str(token).strip())
    for d in list_devices(root):
        if secrets.compare_digest(d.token_hash, digest):
            return d
    return None
