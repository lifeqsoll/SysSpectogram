"""F-07: mode pending auto-rollback."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from sysspectogram.response.mode_rollback import (
    clear_mode_pending,
    load_mode_pending,
    maybe_rollback_mode,
    mode_pending_path,
    schedule_mode_pending,
)


def test_schedule_and_clear(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    out = schedule_mode_pending("soft", rollback_sec=120)
    assert out["scheduled"] is True
    assert mode_pending_path().is_file()
    clear_mode_pending()
    assert load_mode_pending() is None


def test_observe_clears_pending(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    schedule_mode_pending("soft")
    out = schedule_mode_pending("observe")
    assert out["scheduled"] is False
    assert load_mode_pending() is None


def test_rollback_after_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir()
    settings = tmp_path / "state" / "user-settings.json"
    settings.write_text('{"response.mode":"soft"}\n', encoding="utf-8")

    schedule_mode_pending("soft", rollback_sec=1)
    pending = load_mode_pending()
    assert pending is not None
    pending["deadline"] = time.time() - 1
    mode_pending_path().write_text(json.dumps(pending) + "\n", encoding="utf-8")

    class FakeNft:
        def __init__(self) -> None:
            self.unbanned: list[str] = []

        def list_bans(self):
            return ["198.51.100.7"]

        def unban_ip(self, ip: str, dry_run: bool = False) -> str:
            self.unbanned.append(ip)
            return f"unbanned {ip}"

    class FakeWatcher:
        auto_ban_rules = {"bruteforce_ssh"}

    w = FakeWatcher()
    nft = FakeNft()
    assert maybe_rollback_mode(watcher=w, nft=nft) is True
    assert w.auto_ban_rules == set()
    assert nft.unbanned == ["198.51.100.7"]
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["response.mode"] == "observe"
    assert load_mode_pending() is None
