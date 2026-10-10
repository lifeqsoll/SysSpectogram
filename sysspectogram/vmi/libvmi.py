"""Read-only Linux task walker over a libvmi-style session (Phase 3).

The walk logic is independent of the binding: it needs only the primitives in
`VmiSession`. `_default_session` wires them to the libvmi Python bindings.

STATUS: the binding calls in `_default_session` are written against the libvmi
API as documented upstream but are NOT verified on this machine yet. They are
exercised for the first time in the test block on the KVM lab (see plan,
`test-block`). Until then the backend reports itself as unverified.

Safety: read-only. No pause, no write, no kill. Reads are not atomic with the
running guest, so the caller must use the confirmation streak in crossview.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from sysspectogram.vmi.base import TRUST_LAB, GuestTask

MAX_TASKS = 100_000
COMM_LEN = 16


class VmiSession(Protocol):
    def ksym(self, name: str) -> int: ...
    def offset(self, name: str) -> int: ...
    def read_addr(self, va: int) -> int: ...
    def read_u32(self, va: int) -> int: ...
    def read_bytes(self, va: int, size: int) -> bytes: ...
    def kernel_release(self) -> str: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class ProfileBinding:
    """Sidecar JSON next to the ISF profile: `{"kernel_release": "6.x.y-..."}`."""

    kernel_release: str

    @classmethod
    def load(cls, profile: Path) -> ProfileBinding:
        meta = Path(str(profile) + ".meta.json")
        if not meta.is_file():
            raise RuntimeError(f"profile sidecar missing: {meta}")
        data = json.loads(meta.read_text(encoding="utf-8"))
        rel = str(data.get("kernel_release") or "")
        if not rel:
            raise RuntimeError("profile sidecar has no kernel_release")
        return cls(kernel_release=rel)


def walk_linux_tasks(session: VmiSession) -> list[GuestTask]:
    """Walk init_task.tasks (circular list) and read pid and comm for each task."""
    init = session.ksym("init_task")
    off_tasks = session.offset("linux_tasks")
    off_pid = session.offset("linux_pid")
    off_comm = session.offset("linux_name")
    head = init + off_tasks
    cur = session.read_addr(head)
    out: list[GuestTask] = [_read_task(session, init, off_pid, off_comm)]
    steps = 0
    while cur != head and cur != 0:
        steps += 1
        if steps > MAX_TASKS:
            raise RuntimeError("task list did not close; refusing to continue")
        task_va = cur - off_tasks
        out.append(_read_task(session, task_va, off_pid, off_comm))
        cur = session.read_addr(cur)
    return out


def _read_task(session: VmiSession, task_va: int, off_pid: int, off_comm: int) -> GuestTask:
    pid = session.read_u32(task_va + off_pid)
    raw = session.read_bytes(task_va + off_comm, COMM_LEN)
    comm = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return GuestTask(pid=int(pid), comm=comm)


class LibvmiTaskSource:
    name = "libvmi"

    def __init__(
        self,
        domain: str,
        *,
        profile: Path,
        trust: str = TRUST_LAB,
        session_factory: Callable[[str, Path], VmiSession] | None = None,
    ) -> None:
        self.domain = domain
        self.profile = Path(profile)
        self.trust = trust
        self._factory = session_factory or _default_session
        self._session: VmiSession | None = None

    def _ensure(self) -> VmiSession:
        if self._session is None:
            binding = ProfileBinding.load(self.profile)
            session = self._factory(self.domain, self.profile)
            if session.kernel_release() != binding.kernel_release:
                session.close()
                raise RuntimeError(
                    "profile does not match the guest kernel; regenerate the ISF profile"
                )
            self._session = session
        return self._session

    def list_tasks(self) -> list[GuestTask]:
        return walk_linux_tasks(self._ensure())

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


def _default_session(domain: str, profile: Path) -> VmiSession:
    try:
        import libvmi  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on host packages
        raise RuntimeError(
            "libvmi python bindings not installed; see docs/VMI.md (lab setup)"
        ) from exc
    return _LibvmiSession(libvmi, domain, profile)  # pragma: no cover


class _LibvmiSession:  # pragma: no cover - needs a real libvmi and a KVM guest
    """UNVERIFIED adapter. Method names follow upstream libvmi; verify in the test block."""

    def __init__(self, libvmi, domain: str, profile: Path) -> None:
        self._lib = libvmi
        self._vmi = libvmi.Libvmi(domain, config_profile=str(profile))

    def ksym(self, name: str) -> int:
        return int(self._vmi.translate_ksym2v(name))

    def offset(self, name: str) -> int:
        return int(self._vmi.get_offset(name))

    def read_addr(self, va: int) -> int:
        return int(self._vmi.read_addr_va(va, 0))

    def read_u32(self, va: int) -> int:
        return int(self._vmi.read_32_va(va, 0))

    def read_bytes(self, va: int, size: int) -> bytes:
        return bytes(self._vmi.read_va(va, 0, size))

    def kernel_release(self) -> str:
        return str(self._vmi.get_kernel_release())

    def close(self) -> None:
        self._vmi.destroy()
