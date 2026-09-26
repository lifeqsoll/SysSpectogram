"""Optional pack signatures: HMAC-SHA256 sidecar (.sig) with pack signing key."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def load_pack_key(path: Path | None = None, env: str = "SYSSPECTOGRAM_PACK_KEY") -> str | None:
    v = (os.environ.get(env) or "").strip()
    if v:
        return v
    if path and Path(path).exists():
        raw = Path(path).read_text(encoding="utf-8").strip()
        return raw or None
    return None


def ensure_pack_key(path: Path) -> str:
    path = Path(path)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if raw:
            return raw
    import secrets

    path.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_hex(32)
    path.write_text(raw + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return raw


def sign_file(path: Path, key: str) -> Path:
    path = Path(path)
    dig = hmac.new(key.encode("utf-8"), path.read_bytes(), hashlib.sha256).hexdigest()
    sig = path.with_suffix(path.suffix + ".sig")
    sig.write_text(f"{dig}  {path.name}\n", encoding="utf-8")
    return sig


def verify_file(path: Path, key: str, sig_path: Path | None = None) -> bool:
    path = Path(path)
    sig_path = Path(sig_path) if sig_path else path.with_suffix(path.suffix + ".sig")
    if not sig_path.exists():
        return False
    line = sig_path.read_text(encoding="utf-8").strip().split()[0].lower()
    expect = hmac.new(key.encode("utf-8"), path.read_bytes(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, line)
