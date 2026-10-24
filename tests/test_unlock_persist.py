from __future__ import annotations

from pathlib import Path

from sysspectogram.console_unlock import ConsoleUnlock


def test_unlock_persists_across_instances(tmp_path: Path):
    marker = tmp_path / "control.unlocked"
    u = ConsoleUnlock(enabled=True, ttl_sec=0, persist_path=marker)
    code = u.pending_code
    assert u.try_unlock(code)
    assert marker.is_file()
    u2 = ConsoleUnlock(enabled=True, ttl_sec=0, persist_path=marker)
    assert u2.unlocked()
    u2.lock()
    assert not marker.exists()
    u3 = ConsoleUnlock(enabled=True, ttl_sec=0, persist_path=marker)
    assert not u3.unlocked()
