"""Fleet Telegram allowlist (user IDs only) + L3 confirm binding."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from sysspectogram.fleet.store import FleetStore
from sysspectogram.fleet_tg import FleetTelegramBot, parse_allow_users, user_allow_ids


def test_parse_allow_users_empty():
    assert parse_allow_users("") == frozenset()
    assert parse_allow_users("  , , ") == frozenset()


def test_parse_allow_users_comma_separated():
    assert parse_allow_users("111, 222,333") == frozenset({"111", "222", "333"})


def test_parse_allow_users_from_env(monkeypatch):
    monkeypatch.setenv("FLEET_TELEGRAM_ALLOW_USERS", "9, 8")
    assert parse_allow_users() == frozenset({"9", "8"})


def test_user_allow_ids_drops_group_ids():
    assert user_allow_ids(frozenset({"42", "-100123", "0", "7"})) == frozenset({"42", "7"})


def test_allowed_falls_back_to_configured_dm(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(client, FleetStore(tmp_path / "fleet.json"), allow_users=frozenset())
    assert bot.allowed("100") is True
    assert bot.allowed("999") is False


def test_group_without_user_allowlist_denied(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "-100123"
    bot = FleetTelegramBot(client, FleetStore(tmp_path / "fleet.json"), allow_users=frozenset())
    assert bot.allowed("-100123", user_id="7") is False
    client.send_message = MagicMock()
    bot.handle_command("/unlock secret", "-100123", user_id="7")
    client.send_message.assert_not_called()
    bot.handle_command("/use web1", "-100123", user_id="7")
    client.send_message.assert_not_called()


def test_group_id_in_allowlist_does_not_authorize_members(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "-100123"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"-100123"}),
    )
    assert bot.user_ids == frozenset()
    assert bot.allowed("-100123", user_id="7") is False
    client.send_message = MagicMock()
    bot.unlock._unlocked = True  # noqa: SLF001
    bot.handle_command("/attack L2", "-100123", user_id="7")
    client.send_message.assert_not_called()


def test_group_requires_user_in_allowlist(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "-100123"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"42", "-100123"}),
    )
    assert bot.allowed("-100123", user_id="42") is True
    assert bot.allowed("-100123", user_id="7") is False


def test_dm_allowlist_requires_user(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100", "42"}),
    )
    assert bot.allowed("100", user_id="100") is True
    assert bot.allowed("100", user_id="42") is True
    assert bot.allowed("100", user_id="7") is False
    assert bot.allowed("999", user_id="42") is False


def test_handle_command_ignores_non_allowlisted(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    client.send_message = MagicMock()
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100"}),
    )
    bot.handle_command("/menu", "999", user_id="7")
    client.send_message.assert_not_called()


def test_handle_callback_unauthorized(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    client.answer_callback = MagicMock()
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100"}),
    )
    bot.handle_callback(
        {
            "id": "cq1",
            "data": "cmd|status",
            "from": {"id": 7},
            "message": {"chat": {"id": 999}},
        }
    )
    client.answer_callback.assert_called_once_with("cq1", "unauthorized")


def test_confirm_l3_wrong_user_keeps_pending(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100", "1", "2"}),
    )
    bot.unlock._unlocked = True  # noqa: SLF001
    bot.scope = "all"
    pending = {
        "chat_id": "100",
        "user_id": "1",
        "scope": "all",
        "ts": time.time(),
    }
    bot._pending_l3 = pending
    with patch("sysspectogram.fleet_tg.attack") as attack_mock:
        bot.handle_command("/confirm_l3", "100", user_id="2")
        attack_mock.assert_not_called()
        assert bot._pending_l3 is pending
        bot.handle_command("/confirm_l3", "100", user_id="1")
        for _ in range(50):
            if attack_mock.called:
                break
            time.sleep(0.01)
        attack_mock.assert_called_once()
        assert bot._pending_l3 is None


def test_confirm_l3_rejects_other_chat_keeps_pending(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100", "200", "1"}),
    )
    bot.unlock._unlocked = True  # noqa: SLF001
    pending = {
        "chat_id": "100",
        "user_id": "1",
        "scope": "all",
        "ts": time.time(),
    }
    bot._pending_l3 = pending
    with patch("sysspectogram.fleet_tg.attack") as attack_mock:
        # chat 200 is not configured → silent deny at allowed()
        bot.handle_command("/confirm_l3", "200", user_id="1")
        attack_mock.assert_not_called()
        assert bot._pending_l3 is pending
