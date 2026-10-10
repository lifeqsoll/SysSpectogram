"""Deterministic task source for tests and the lab demo. Trust is always `lab`."""

from __future__ import annotations

from sysspectogram.vmi.base import TRUST_LAB, GuestTask


class MockGuestTaskSource:
    name = "mock"
    trust = TRUST_LAB

    def __init__(self, tasks: list[GuestTask] | None = None) -> None:
        self._tasks = list(tasks or [])

    def set_tasks(self, tasks: list[GuestTask]) -> None:
        self._tasks = list(tasks)

    def list_tasks(self) -> list[GuestTask]:
        return list(self._tasks)
