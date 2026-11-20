"""Kill-attempt alert policy (mirrors agent/src/trust.rs)."""

from __future__ import annotations

import os
from pathlib import Path

from sysspectogram.trusted_pids import collect_trusted_pids, expand_descendant_pids


def kill_alert_severity(sig: int) -> str | None:
    """Mirror of Rust ``kill_alert_severity`` for regression docs/tests."""
    if sig == 0:
        return None
    if sig == 15:
        return None
    if sig in {1, 10, 12}:
        return "low"
    if sig in {2, 3, 6, 9, 19, 20, 23, 4, 5, 7, 8, 11, 16, 31}:
        return "critical"
    return "low"


def signal_name(sig: int) -> str:
    return {
        0: "SIG0",
        1: "SIGHUP",
        2: "SIGINT",
        9: "SIGKILL",
        10: "SIGUSR1",
        12: "SIGUSR2",
        15: "SIGTERM",
        19: "SIGSTOP",
    }.get(sig, "SIGNAL")


def test_sig0_never_alerts():
    assert kill_alert_severity(0) is None


def test_sigkill_critical_sigusr_low():
    assert kill_alert_severity(9) == "critical"
    assert signal_name(9) == "SIGKILL"
    assert kill_alert_severity(1) == "low"
    assert kill_alert_severity(10) == "low"


def test_guard_descendants_are_trusted(tmp_path: Path):
    guard_pf = tmp_path / "guard.pid"
    agent_pf = tmp_path / "agent.pid"
    guard_pf.write_text(f"{os.getpid()}\n", encoding="utf-8")
    agent_pf.write_text(f"{os.getpid()}\n", encoding="utf-8")
    trusted = collect_trusted_pids(
        agent_pidfile=agent_pf,
        guard_pidfile=guard_pf,
        include_descendants=True,
    )
    assert os.getpid() in trusted
    # kill(agent, 0) from this process would be trusted → 0 alerts
    assert kill_alert_severity(0) is None


def test_foreign_sigkill_would_alert():
    # Untrusted sender + SIGKILL → one critical (policy level).
    assert kill_alert_severity(9) == "critical"
    foreign = 999_999_999
    trusted = expand_descendant_pids({os.getpid()})
    assert foreign not in trusted


def test_telegram_kill_text_includes_signal_and_parent():
    from types import SimpleNamespace

    from sysspectogram.notify_telegram import TelegramClient
    from sysspectogram.telegram_bot import TelegramBot

    sent: list[str] = []

    class FakeClient(TelegramClient):
        def __init__(self) -> None:
            super().__init__(token="t", chat_id="1")

        @property
        def configured(self) -> bool:  # type: ignore[override]
            return True

        def send_message(self, text, reply_markup=None, **kwargs):  # noqa: ANN001
            sent.append(text)
            return {"ok": True}

        def send_photo(self, *a, **k):  # noqa: ANN001
            return {"ok": True}

    bot = TelegramBot(FakeClient(), lang="en")
    alert = SimpleNamespace(
        rule_id="agent_kirk_agent_kill_attempt",
        severity="critical",
        message="kill/signal toward agent pid=1 SIGKILL(9) from uid=0",
        pid=4242,
        ppid=7,
        comm="evil",
        path=None,
        extras={
            "signal": 9,
            "signal_name": "SIGKILL",
            "parent_pid": 7,
            "parent_comm": "bash",
        },
    )
    bot.send_agent_alert(alert)
    assert sent
    blob = sent[0]
    assert "SIGKILL" in blob
    assert "bash" in blob or "parent" in blob.lower()
