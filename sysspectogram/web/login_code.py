"""One-shot dashboard login code → ss_session (read metrics; not control unlock)."""

from __future__ import annotations

import secrets
import time
from pathlib import Path

from sysspectogram.console_unlock import CODE_ALPHABET, DEFAULT_CODE_LEN

DEFAULT_LOGIN_TTL_SEC = 300.0


class WebLoginCode:
    """Alphanumeric one-time code printed at web start; mints a session only."""

    def __init__(
        self,
        *,
        persist_path: Path | str | None = None,
        code_len: int = DEFAULT_CODE_LEN,
        ttl_sec: float = DEFAULT_LOGIN_TTL_SEC,
    ) -> None:
        self.code_len = max(6, int(code_len))
        self.ttl_sec = float(ttl_sec)
        self.persist_path = Path(persist_path) if persist_path else None
        self._code: str | None = None
        self._deadline = 0.0
        self._fails: list[float] = []
        self.begin()

    def _gen(self) -> str:
        n = len(CODE_ALPHABET)
        return "".join(CODE_ALPHABET[secrets.randbelow(n)] for _ in range(self.code_len))

    def begin(self) -> str:
        self._code = self._gen()
        self._deadline = time.time() + self.ttl_sec if self.ttl_sec > 0 else 0.0
        self._fails = []
        self._persist()
        return self._code

    def _persist(self) -> None:
        if not self.persist_path or not self._code:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            self.persist_path.write_text(self._code + "\n", encoding="utf-8")
            self.persist_path.chmod(0o600)
        except OSError:
            pass

    def _clear_persist(self) -> None:
        if not self.persist_path:
            return
        try:
            if self.persist_path.is_file():
                self.persist_path.unlink()
        except OSError:
            pass

    def _expired(self) -> bool:
        if not self._code:
            return True
        if self.ttl_sec <= 0:
            return False
        return time.time() > self._deadline

    @property
    def pending_code(self) -> str | None:
        if self._expired():
            return self.begin()
        return self._code

    @staticmethod
    def normalize(code: str) -> str:
        return str(code).strip().upper().replace(" ", "").replace("-", "")

    def try_consume(self, code: str) -> bool:
        if self._expired() or not self._code:
            self.begin()
            return False
        now = time.time()
        self._fails = [t for t in self._fails if now - t < 300.0]
        if len(self._fails) >= 8:
            return False
        got = self.normalize(code)
        if len(got) != len(self._code):
            self._fails.append(now)
            return False
        ok = secrets.compare_digest(got, self._code)
        if not ok:
            self._fails.append(now)
            return False
        self._code = None
        self._deadline = 0.0
        self._fails = []
        self._clear_persist()
        return True
