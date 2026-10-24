from __future__ import annotations

import time
from unittest.mock import MagicMock

from sysspectogram.console_unlock import CODE_ALPHABET, ConsoleUnlock
from sysspectogram.response.actions import kill_pid
from sysspectogram.response.tokens import TokenStore
from sysspectogram.telegram_bot import TelegramBot


def test_console_unlock_shared():
    u = ConsoleUnlock(enabled=True, ttl_sec=0, code_ttl_sec=300)
    assert not u.unlocked()
    code = u.pending_code
    assert code and len(code) == 10
    assert all(c in CODE_ALPHABET for c in code)
    assert u.try_unlock(code.lower())  # case-insensitive
    assert u.unlocked()
    # infinite session
    assert u.unlocked()
    u.lock()
    assert not u.unlocked()


def test_console_unlock_code_expires(monkeypatch):
    import sysspectogram.console_unlock as cu

    now = 1_700_000_000.0
    monkeypatch.setattr(cu.time, "time", lambda: now)
    u = ConsoleUnlock(enabled=True, ttl_sec=0, code_ttl_sec=60)
    first = u.pending_code
    assert first
    monkeypatch.setattr(cu.time, "time", lambda: now + 61)
    assert u.try_unlock(first) is False
    assert u.pending_code != first


def test_console_unlock_session_ttl_zero_never_expires(monkeypatch):
    import sysspectogram.console_unlock as cu

    now = 1_700_000_000.0
    monkeypatch.setattr(cu.time, "time", lambda: now)
    u = ConsoleUnlock(enabled=True, ttl_sec=0, code_ttl_sec=300)
    code = u.pending_code
    assert u.try_unlock(code)
    monkeypatch.setattr(cu.time, "time", lambda: now + 86400 * 30)
    assert u.unlocked()


def test_kill_pid_expect_comm_mismatch(monkeypatch, tmp_path):
    assert "refusing" in kill_pid(1, dry_run=True, expect_comm="x")
    assert "gone" in kill_pid(999999, dry_run=True, expect_comm="nosuch").lower() or "skipped" in kill_pid(
        999999, dry_run=True, expect_comm="nosuch"
    ).lower()


def test_console_unlock_flow():
    client = MagicMock()
    client.configured = True
    client.chat_id = "111"
    bot = TelegramBot(
        client,
        tokens=TokenStore(secret="x"),
        host_id="h",
        require_console_unlock=True,
        unlock_ttl_sec=0,
    )
    assert not bot.session_unlocked()
    code = bot._unlock_code
    assert code and len(code) >= 8
    bot.handle_command("/status", "111")
    assert any("LOCKED" in str(c) for c in client.send_message.call_args_list)
    client.send_message.reset_mock()
    bot.handle_command(f"/unlock {code}", "111")
    assert bot.session_unlocked()
    bot.handle_command("/lock", "111")
    assert not bot.session_unlocked()
    assert bot._unlock_code and bot._unlock_code != code


def test_unlock_bruteforce_rotates_code():
    client = MagicMock()
    client.configured = True
    client.chat_id = "111"
    bot = TelegramBot(
        client,
        tokens=TokenStore(secret="x"),
        host_id="h",
        require_console_unlock=True,
        unlock_ttl_sec=0,
    )
    first = bot._unlock_code
    for _ in range(5):
        assert bot.try_unlock("AAAAAAAAAA") is False
    assert bot._unlock_code != first
    assert not bot.session_unlocked()
