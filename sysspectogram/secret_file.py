"""Atomic 0600 secret writes + Telegram .env value validation."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

_BOT_TOKEN_RE = re.compile(r"^\d{1,12}:(?:TEST_TOKEN|[A-Za-z0-9_-]{30,})$")
_CHAT_ID_RE = re.compile(r"^-?\d{1,20}$")


def validate_bot_token(value: str) -> str:
    v = (value or "").strip()
    if any(c in v for c in ("\n", "\r", "\0")):
        raise ValueError("bot token must not contain newlines or NUL")
    if not _BOT_TOKEN_RE.match(v):
        raise ValueError("bot token format invalid")
    return v


def validate_chat_id(value: str) -> str:
    v = (value or "").strip()
    if any(c in v for c in ("\n", "\r", "\0")):
        raise ValueError("chat id must not contain newlines or NUL")
    if not _CHAT_ID_RE.match(v):
        raise ValueError("chat id format invalid")
    return v


def write_secret_file(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` as owner-only (0600) via tmp + O_EXCL + replace.

    Refuses to follow a symlink at ``path``. Always ends with a trailing newline
    when ``text`` is non-empty and does not already end with one.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise OSError(f"refusing to write through symlink: {path}")
    body = text if (not text or text.endswith("\n")) else text + "\n"
    data = body.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def ensure_secret_mode(path: Path) -> None:
    """If ``path`` exists and mode is wider than 0600, chmod 600."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
