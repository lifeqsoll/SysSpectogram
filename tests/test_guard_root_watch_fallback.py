"""Python root-watch fallback when the agent is down."""

from __future__ import annotations

from sysspectogram.guard import _root_watch_python_should_poll


def test_fallback_runs_when_agent_binary_missing() -> None:
    assert _root_watch_python_should_poll(True, None) is True
    assert _root_watch_python_should_poll(False, None) is True


def test_fallback_pauses_when_agent_alive() -> None:
    assert _root_watch_python_should_poll(True, 4242) is False
