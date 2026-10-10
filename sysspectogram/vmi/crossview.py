"""Cross-view between the guest agent's process view and the hypervisor task list.

A task visible to the hypervisor but absent from the in-guest view is a candidate
for hiding (`vmi_task_hidden`). The check needs `confirm` consecutive passes before it
alerts, and each hidden pid alerts once until it disappears from the hypervisor view.
Guest-only tasks (races) are not reported in v1.0; `vmi_task_missing` is reserved.

Output is an alert dict with the same shape as other guard alerts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from sysspectogram.vmi.base import GuestTask, GuestTaskSource

RULE_HIDDEN = "vmi_task_hidden"
RULE_MISSING = "vmi_task_missing"
KERNEL_PIDS_MAX = 2  # pid 0 and 1 are never reported as hidden


@dataclass
class CrossViewState:
    confirm: int = 2
    streaks: dict[int, int] = field(default_factory=dict)
    alerted: set[int] = field(default_factory=set)


def compare(
    guest_pids: Iterable[int],
    hypervisor_tasks: Iterable[GuestTask],
    state: CrossViewState,
) -> list[GuestTask]:
    """Return hypervisor-only tasks that passed the confirmation streak."""
    guest = set(int(p) for p in guest_pids)
    hv = {t.pid: t for t in hypervisor_tasks if t.pid > KERNEL_PIDS_MAX}
    confirmed: list[GuestTask] = []
    seen_now: set[int] = set()
    for pid, task in hv.items():
        if pid in guest:
            continue
        seen_now.add(pid)
        state.streaks[pid] = state.streaks.get(pid, 0) + 1
        if state.streaks[pid] >= state.confirm:
            confirmed.append(task)
    for pid in list(state.streaks):
        if pid not in seen_now:
            del state.streaks[pid]
    return confirmed


def build_alert(task: GuestTask, source: GuestTaskSource, host_id: str) -> dict:
    return {
        "type": "agent",
        "kind": "vmi",
        "rule_id": RULE_HIDDEN,
        "severity": "high",
        "host_id": host_id,
        "pid": task.pid,
        "comm": task.comm,
        "ts": time.time(),
        "message": (
            f"hypervisor sees pid={task.pid} comm={task.comm!r} that the guest view does not"
        ),
        "extras": {"source": source.name, "trust": source.trust},
    }


def check(
    guest_pids: Iterable[int],
    source: GuestTaskSource,
    state: CrossViewState,
    host_id: str,
) -> list[dict]:
    """One cross-view pass. Raises whatever the source raises; caller decides fail-open."""
    tasks = source.list_tasks()
    hidden = compare(guest_pids, tasks, state)
    # Forget pids that are gone, so a pid that comes back alerts again.
    state.alerted &= {t.pid for t in tasks}
    fresh = [t for t in hidden if t.pid not in state.alerted]
    state.alerted.update(t.pid for t in fresh)
    return [build_alert(t, source, host_id) for t in fresh]
