from __future__ import annotations

from sysspectogram.vmi.base import TRUST_LAB, GuestTask
from sysspectogram.vmi.crossview import RULE_HIDDEN, CrossViewState, check
from sysspectogram.vmi.mock import MockGuestTaskSource


def _source(pids: list[int]) -> MockGuestTaskSource:
    return MockGuestTaskSource([GuestTask(pid=p, comm=f"p{p}") for p in pids])


def test_hidden_task_needs_confirmation_streak():
    src = _source([100, 200])
    state = CrossViewState(confirm=2)
    assert check([100], src, state, "h") == []
    alerts = check([100], src, state, "h")
    assert [a["rule_id"] for a in alerts] == [RULE_HIDDEN]
    assert alerts[0]["pid"] == 200


def test_hidden_task_alerts_once_until_it_disappears():
    src = _source([100, 200])
    state = CrossViewState(confirm=1)
    assert len(check([100], src, state, "h")) == 1
    assert check([100], src, state, "h") == []
    src.set_tasks([GuestTask(pid=100, comm="p100")])
    assert check([100], src, state, "h") == []
    src.set_tasks([GuestTask(pid=100, comm="p100"), GuestTask(pid=200, comm="p200")])
    assert len(check([100], src, state, "h")) == 1


def test_mock_source_is_lab_trust():
    assert MockGuestTaskSource().trust == TRUST_LAB


def test_kernel_pids_never_reported():
    src = _source([0, 1, 2])
    state = CrossViewState(confirm=1)
    assert check([], src, state, "h") == []
