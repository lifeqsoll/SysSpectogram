"""One-shot dashboard login code → ss_session (read metrics; not control unlock)."""

from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

from sysspectogram.console_unlock import CODE_ALPHABET, DEFAULT_CODE_LEN

DEFAULT_LOGIN_TTL_SEC = 300.0


class WebLoginCode:
    """Alphanumeric one-time code printed at web start; mints a session only.

    After a successful consume the next code is written immediately to
    ``state/web.login`` (0600). Expiry rotates the code in-process so the file
    does not keep a dead code.
    """

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
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self.begin()

    def _gen(self) -> str:
        n = len(CODE_ALPHABET)
        return "".join(CODE_ALPHABET[secrets.randbelow(n)] for _ in range(self.code_len))

    def begin(self) -> str:
        with self._lock:
            return self._begin_locked()

    def _begin_locked(self) -> str:
        self._code = self._gen()
        self._deadline = time.time() + self.ttl_sec if self.ttl_sec > 0 else 0.0
        self._fails = []
        self._persist_locked()
        self._arm_locked()
        return self._code

    def close(self) -> None:
        """Cancel rotation and remove the on-disk code (web is stopping)."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._code = None
            self._deadline = 0.0
            path = self.persist_path
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _arm_locked(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self.ttl_sec <= 0 or not self._code:
            return
        delay = max(0.05, self._deadline - time.time())
        timer = threading.Timer(delay, self._rotate_if_expired)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _rotate_if_expired(self) -> None:
        with self._lock:
            if self._expired_locked():
                self._begin_locked()
            else:
                self._arm_locked()

    def _persist_locked(self) -> None:
        if not self.persist_path or not self._code:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.persist_path.parent, 0o700)
            except OSError:
                pass
            text = f"{self._code}\n{self._deadline}\n{os.getpid()}\n"
            tmp = self.persist_path.with_name(self.persist_path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, text.encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, self.persist_path)
        except OSError:
            pass

    def _expired_locked(self) -> bool:
        if not self._code:
            return True
        if self.ttl_sec <= 0:
            return False
        return time.time() > self._deadline

    @property
    def pending_code(self) -> str | None:
        with self._lock:
            expired = self._expired_locked()
            code = self._code
        if expired:
            return self.begin()
        return code

    @staticmethod
    def normalize(code: str) -> str:
        return str(code).strip().upper().replace(" ", "").replace("-", "")

    def try_consume(self, code: str) -> bool:
        with self._lock:
            if self._expired_locked() or not self._code:
                self._begin_locked()
                return False
            now = time.time()
            self._fails = [t for t in self._fails if now - t < 300.0]
            if len(self._fails) >= 8:
                return False
            got = self.normalize(code)
            if len(got) != len(self._code) or not secrets.compare_digest(got, self._code):
                self._fails.append(now)
                return False
            self._begin_locked()
            return True


def read_login_code(path: Path) -> tuple[str | None, float | None, int | None]:
    """Return ``(code, deadline, pid)`` from ``state/web.login``."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None, None, None
    if not lines or not lines[0].strip():
        return None, None, None
    deadline = None
    if len(lines) > 1:
        try:
            deadline = float(lines[1])
        except ValueError:
            deadline = None
    pid = None
    if len(lines) > 2:
        try:
            pid = int(lines[2])
        except ValueError:
            pid = None
    return lines[0].strip(), deadline, pid
