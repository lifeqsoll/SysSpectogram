"""Probe IMA / Secure Boot / TPM for kirk trust labeling."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class KirkTrustReport:
    """Honest trust label for in-guest integrity."""

    trust: str  # best-effort | measured
    ima_present: bool
    ima_measurements: int
    secure_boot: bool | None  # None = unknown / not EFI
    tpm_present: bool
    details: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ima_ascii_path() -> Path:
    return Path("/sys/kernel/security/ima/ascii_runtime_measurements")


def _count_ima_lines() -> tuple[bool, int, list[str]]:
    path = _ima_ascii_path()
    details: list[str] = []
    if not path.exists():
        details.append("IMA ascii_runtime_measurements missing")
        return False, 0, details
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        # Unreadable ≠ usable — do not claim measured.
        details.append(f"IMA unreadable ({exc})")
        return False, 0, details
    lines = [ln for ln in text.splitlines() if ln.strip()]
    details.append(f"IMA measurements={len(lines)}")
    return True, len(lines), details


def _secure_boot() -> tuple[bool | None, list[str]]:
    details: list[str] = []
    efivars = Path("/sys/firmware/efi/efivars")
    if not efivars.is_dir():
        details.append("not EFI (or efivars unavailable)")
        return None, details
    # SecureBoot-*-8be4df61-93ca-11d2-aa0d-00e098032b8c
    matches = list(efivars.glob("SecureBoot-*"))
    if not matches:
        details.append("EFI but SecureBoot var not found")
        return None, details
    try:
        raw = matches[0].read_bytes()
        # EFI var: 4 byte attributes + data; last data byte 1 = enabled
        enabled = len(raw) >= 5 and raw[-1] == 1
        details.append(f"SecureBoot={'on' if enabled else 'off'}")
        return enabled, details
    except OSError as exc:
        details.append(f"SecureBoot unreadable ({exc})")
        return None, details


def _tpm_present() -> tuple[bool, list[str]]:
    details: list[str] = []
    if Path("/dev/tpm0").exists() or Path("/dev/tpmrm0").exists():
        details.append("TPM device node present")
        return True, details
    tpm_class = Path("/sys/class/tpm")
    if tpm_class.is_dir() and any(tpm_class.iterdir()):
        details.append("TPM sysfs class present")
        return True, details
    details.append("no TPM device")
    return False, details


def probe_kirk_trust(*, require_tpm: bool = False) -> KirkTrustReport:
    """
    measured = IMA readable with ≥1 measurement AND (Secure Boot on OR TPM present).
    If require_tpm=True, TPM is mandatory for measured.
    Otherwise best-effort.
    """
    details: list[str] = []
    ima_ok, n_meas, d1 = _count_ima_lines()
    details.extend(d1)
    sb, d2 = _secure_boot()
    details.extend(d2)
    tpm, d3 = _tpm_present()
    details.extend(d3)

    ima_usable = ima_ok and n_meas > 0
    if require_tpm:
        measured = ima_usable and tpm and (sb is True or sb is None)
    else:
        measured = ima_usable and (sb is True or tpm)

    trust = "measured" if measured else "best-effort"
    if measured:
        details.append("trust=measured")
    else:
        details.append("trust=best-effort (need readable IMA measurements + SecureBoot and/or TPM)")

    return KirkTrustReport(
        trust=trust,
        ima_present=ima_ok,
        ima_measurements=n_meas,
        secure_boot=sb,
        tpm_present=tpm,
        details=details,
    )


def recent_ima_module_hashes(limit: int = 50) -> list[dict[str, str]]:
    """
    Best-effort parse of IMA ascii log for module-related lines.
    Format varies by kernel; we keep raw templatehash/filedatahash fields when present.
    """
    path = _ima_ascii_path()
    out: list[dict[str, str]] = []
    if not path.exists():
        return out
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in reversed(lines):
        if "module" not in line.lower() and "finit_module" not in line.lower():
            # still include boot_aggregate sparingly — skip
            if "/lib/modules/" not in line and "ko" not in line:
                continue
        parts = line.split()
        rec = {"raw": line[:240]}
        if len(parts) >= 4:
            rec["template"] = parts[2] if len(parts) > 2 else ""
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def ima_watch_new_lines(state_path: Path) -> list[str]:
    """
    Return new IMA lines since last call (state file stores byte offset / line count).
    Used by guard to emit agent_kirk_ima_mismatch-style notices on growth with module markers.
    """
    ima = _ima_ascii_path()
    if not ima.exists():
        return []
    try:
        data = ima.read_bytes()
    except OSError:
        return []
    prev = 0
    if state_path.exists():
        try:
            prev = int(state_path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            prev = 0
    if len(data) < prev:
        prev = 0
    chunk = data[prev:]
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(str(len(data)), encoding="utf-8")
    if not chunk:
        return []
    text = chunk.decode("utf-8", errors="replace")
    return [ln for ln in text.splitlines() if ln.strip()]
