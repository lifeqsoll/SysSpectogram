"""Optional sysfs registration for packaging/kmod/sysspectogram_wd."""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)

SYSFS = Path("/sys/kernel/sysspectogram_wd/protected_pids")


def kernel_module_present() -> bool:
    return SYSFS.is_file()


def register_pid(pid: int) -> bool:
    if not kernel_module_present():
        return False
    try:
        SYSFS.write_text(f"add {int(pid)}\n", encoding="utf-8")
        return True
    except OSError as exc:
        log.warning("kernel_protect register failed: %s", exc)
        return False


def unregister_pid(pid: int) -> bool:
    if not kernel_module_present():
        return False
    try:
        SYSFS.write_text(f"del {int(pid)}\n", encoding="utf-8")
        return True
    except OSError as exc:
        log.warning("kernel_protect unregister failed: %s", exc)
        return False
