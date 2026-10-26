"""Host-console pairing code for Telegram / Mini App control plane."""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Callable

# Steam-like alphabet: no 0/O/1/I/L (ambiguous on phones).
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_CODE_LEN = 10
DEFAULT_CODE_TTL_SEC = 300.0  # code expires like Steam Guard (~5 min)
SESSION_MARKER = "control.unlocked"


class ConsoleUnlock:
    """Alphanumeric host pairing code; stolen bot token alone cannot unlock.

    After a successful unlock, the session stays open until /lock or process
    restart when ttl_sec <= 0 (away-from-PC ops). The *code* itself expires
    after code_ttl_sec and is rotated on the host.

    When persist_path is set and ttl_sec <= 0, unlock survives guard restart
    until /lock (fleet-friendly — no morning re-unlock ritual).
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        ttl_sec: float = 0.0,
        code_ttl_sec: float = DEFAULT_CODE_TTL_SEC,
        code_len: int = DEFAULT_CODE_LEN,
        on_code: Callable[[str | None], None] | None = None,
        persist_path: Path | str | None = None,
    ) -> None:
        self.enabled = enabled
        self.ttl_sec = float(ttl_sec)
        self.code_ttl_sec = float(code_ttl_sec)
        # Non-expiring codes must stay long enough that unauth rate-limited
        # brute force stays impractical (audit R-04).
        want_len = max(6, int(code_len))
        if self.code_ttl_sec <= 0 and want_len < 10:
            import logging

            logging.getLogger(__name__).warning(
                "unlock_code_len=%s with unlock_code_ttl_sec<=0 raised to 10",
                want_len,
            )
            want_len = 10
        self.code_len = want_len
        self.on_code = on_code
        self.persist_path = Path(persist_path) if persist_path else None
        self._code: str | None = None
        self._code_deadline = 0.0
        self._unlocked = not enabled
        self._deadline = 0.0
        self._fails: list[float] = []
        if enabled:
            if self.ttl_sec <= 0:
                import logging

                logging.getLogger(__name__).warning(
                    "console unlock ttl_sec=0: session persists via control.unlocked; "
                    "same-UID processes can clear the gate (see SECURITY.md)"
                )
            if self.ttl_sec <= 0 and self._load_persisted():
                self._unlocked = True
                self._code = None
                self._notify(None)
            else:
                self.begin()

    def _gen_code(self) -> str:
        n = len(CODE_ALPHABET)
        return "".join(CODE_ALPHABET[secrets.randbelow(n)] for _ in range(self.code_len))

    def begin(self) -> str:
        self._code = self._gen_code()
        self._code_deadline = time.time() + self.code_ttl_sec if self.code_ttl_sec > 0 else 0.0
        self._unlocked = False
        self._deadline = 0.0
        self._fails = []
        self._notify(self._code)
        return self._code

    def _notify(self, code: str | None) -> None:
        if self.on_code:
            try:
                self.on_code(code)
            except Exception:
                pass

    def _code_expired(self) -> bool:
        if not self._code:
            return True
        if self.code_ttl_sec <= 0:
            return False
        return time.time() > self._code_deadline

    def _ensure_fresh_code(self) -> str | None:
        """Rotate expired unused codes so state/unlock.code stays valid."""
        if not self.enabled:
            return None
        if self._unlocked:
            return None
        if self._code and not self._code_expired():
            return self._code
        return self.begin()

    @property
    def pending_code(self) -> str | None:
        if not self.enabled or self._unlocked:
            return None
        return self._ensure_fresh_code()

    def unlocked(self) -> bool:
        if not self.enabled:
            return True
        if not self._unlocked:
            return False
        if self.ttl_sec > 0 and time.time() > self._deadline:
            self._unlocked = False
            return False
        return True

    @staticmethod
    def normalize(code: str) -> str:
        return str(code).strip().upper().replace(" ", "").replace("-", "")

    def code_matches(self, code: str) -> bool:
        """Constant-time check without recording failures (for unauth web probes)."""
        if not self.enabled:
            return True
        if self._code_expired() or not self._code:
            return False
        got = self.normalize(code)
        if len(got) != len(self._code):
            return False
        return secrets.compare_digest(got, self._code)

    def try_unlock(self, code: str) -> bool:
        if not self.enabled:
            self._unlocked = True
            return True
        if self._code_expired():
            self.begin()
            return False
        if not self._code:
            return False
        now = time.time()
        self._fails = [t for t in self._fails if now - t < 300.0]
        if len(self._fails) >= 8:
            return False
        got = self.normalize(code)
        # compare_digest needs equal length
        if len(got) != len(self._code):
            self._fails.append(now)
            if len(self._fails) >= 5:
                self.begin()
            return False
        ok = secrets.compare_digest(got, self._code)
        if ok:
            self._unlocked = True
            if self.ttl_sec > 0:
                self._deadline = time.time() + self.ttl_sec
            else:
                self._deadline = 0.0  # infinite session
                self._persist_unlocked()
            self._code = None
            self._code_deadline = 0.0
            self._fails = []
            self._notify(None)  # code consumed
            return True
        self._fails.append(now)
        if len(self._fails) >= 5:
            self.begin()
        return False

    def lock(self) -> str:
        self._clear_persisted()
        return self.begin()

    def _persist_unlocked(self) -> None:
        if not self.persist_path or self.ttl_sec > 0:
            return
        try:
            from sysspectogram.secret_file import write_secret_file

            # Marker is intentional "1" only — arbitrary file content must not unlock (I-03).
            write_secret_file(self.persist_path, "1\n")
        except OSError:
            pass

    def _clear_persisted(self) -> None:
        if not self.persist_path:
            return
        try:
            self.persist_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _load_persisted(self) -> bool:
        if not self.persist_path:
            return False
        path = self.persist_path
        # Symlink or non-regular → refuse (same-UID malware could point at attacker file).
        if path.is_symlink() or not path.is_file():
            return False
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return False
        # Exact marker only — "pwned", empty, or padded values do not unlock.
        return raw == "1\n" or raw.strip() == "1"

    @property
    def fail_count(self) -> int:
        now = time.time()
        self._fails = [t for t in self._fails if now - t < 300.0]
        return len(self._fails)

    def status_label(self) -> str:
        if not self.enabled:
            return "unlocked (gate off)"
        return "unlocked" if self.unlocked() else "LOCKED"
