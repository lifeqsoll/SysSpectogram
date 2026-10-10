"""VMI task-source interface. Read-only by design: no pause, no write, no kill."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

TRUST_LAB = "lab"
TRUST_OUT_OF_BAND = "out-of-band"


@dataclass(frozen=True)
class GuestTask:
    pid: int
    comm: str


class GuestTaskSource(Protocol):
    """A source of guest task lists seen from the hypervisor side."""

    name: str
    trust: str  # TRUST_LAB or TRUST_OUT_OF_BAND, decided by deployment (ADR 0003)

    def list_tasks(self) -> list[GuestTask]:
        """Return the guest task list. Raise RuntimeError when the backend is unusable."""
        ...
