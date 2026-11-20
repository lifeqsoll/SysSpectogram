"""NftBackend must come from backend_from_config in CLI/bot defaults."""

from __future__ import annotations

from unittest import mock

from sysspectogram.response.actions import backend_from_config


def test_perimeter_cli_uses_config_never_ban(monkeypatch) -> None:
    from sysspectogram import cli

    captured: dict = {}

    class FakeWatcher:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, duration_sec=None):
            return None

    monkeypatch.setattr("sysspectogram.perimeter.watcher.PerimeterWatcher", FakeWatcher)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda _p: {
            "perimeter": {},
            "recon": {},
            "host": {},
            "response": {"never_ban_cidrs": ["203.0.113.10/32"]},
            "ssh": {"port": 22},
        },
    )
    args = mock.Mock(config=None, denylist=None, jsonl_out=None, no_recon=True, poll=None, duration=None)
    assert cli._cmd_watch_perimeter(args) == 0
    nft = captured.get("nft")
    assert nft is not None
    assert "203.0.113.10/32" in [str(c) for c in nft.never_ban_cidrs]


def test_bot_default_backend_from_config() -> None:
    from sysspectogram.telegram_bot import TelegramBot

    class FakeClient:
        configured = False

    bot = TelegramBot(
        FakeClient(),  # type: ignore[arg-type]
        config={"response": {"never_ban_cidrs": ["198.51.100.7/32"]}, "ssh": {"port": 22}},
    )
    assert "198.51.100.7/32" in [str(c) for c in bot.nft.never_ban_cidrs]
    # Sanity: factory produces the same policy.
    be = backend_from_config(
        {"response": {"never_ban_cidrs": ["198.51.100.7/32"]}, "ssh": {"port": 22}}
    )
    assert list(be.never_ban_cidrs) == list(bot.nft.never_ban_cidrs)
