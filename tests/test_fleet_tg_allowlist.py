"""Fleet Telegram allowlist (FLEET_TELEGRAM_ALLOW_USERS)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from sysspectogram.fleet.store import FleetStore
from sysspectogram.fleet_tg import FleetTelegramBot, parse_allow_users


def test_parse_allow_users_empty():
    assert parse_allow_users("") == frozenset()
    assert parse_allow_users("  , , ") == frozenset()


def test_parse_allow_users_comma_separated():
    assert parse_allow_users("111, 222,333") == frozenset({"111", "222", "333"})


def test_parse_allow_users_from_env(monkeypatch):
    monkeypatch.setenv("FLEET_TELEGRAM_ALLOW_USERS", "9, 8")
    assert parse_allow_users() == frozenset({"9", "8"})


def test_allowed_falls_back_to_configured_chat(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(client, FleetStore(tmp_path / "fleet.json"), allow_users=frozenset())
    assert bot.allowed("100") is True
    assert bot.allowed("999") is False


def test_allowlist_rejects_others(tmp_path: Path):
    client = MagicMock()
    client.chat_id = "100"
    bot = FleetTelegramBot(
        client,
        FleetStore(tmp_path / "fleet.json"),
        allow_users=frozenset({"100", "42"}),
    )
    assert bot.allowed("100") is True
    assert bot.allowed("999", user_id="42") is True
    assert bot.allowed("999", user_id="7") is False
    assert bot.allowed("999") is False


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
