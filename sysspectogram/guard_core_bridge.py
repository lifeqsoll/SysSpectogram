"""Call the guard-core binary for a metrics shadow and small parsers."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


def find_bin(explicit: str | Path | None = None) -> Path | None:
    """Locate `sysspectogram-guard-core`.

    Order (security): explicit config → bundled target/ → PATH last.
    """
    if explicit:
        cand = Path(explicit)
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand.resolve()
        return None
    root = Path(__file__).resolve().parents[1]
    for rel in (
        "guard-core/target/release/sysspectogram-guard-core",
        "guard-core/target/debug/sysspectogram-guard-core",
        "bin/sysspectogram-guard-core",
    ):
        cand = root / rel
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand.resolve()
    found = shutil.which("sysspectogram-guard-core")
    if found:
        return Path(found).resolve()
    return None


def verify_bin_sha256(path: Path, expect_hex: str | None) -> bool:
    """If ``expect_hex`` is set, require matching SHA-256 of the binary."""
    if not expect_hex:
        return True
    want = expect_hex.strip().lower()
    if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
        return False
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return False
    return digest == want


def run_once_metrics(
    bin_path: str | Path | None = None,
    *,
    timeout: float = 5.0,
    expect_sha256: str | None = None,
) -> dict[str, Any] | None:
    """One CPU/mem sample from `guard-core metrics` (falls back to `--once`)."""
    exe = Path(bin_path) if bin_path else find_bin()
    if exe is None or not exe.is_file():
        return None
    if not verify_bin_sha256(exe, expect_sha256):
        return None
    for args in ([str(exe), "metrics"], [str(exe), "--once"]):
        try:
            proc = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            continue
        line = (proc.stdout or "").strip().splitlines()
        if not line:
            continue
        try:
            data = json.loads(line[-1])
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        try:
            cpu = float(data.get("cpu_percent") or 0.0)
            mem = float(data.get("mem_percent") or 0.0)
        except (TypeError, ValueError):
            continue
        return {
            "schema_version": data.get("schema_version"),
            "cpu_percent": cpu,
            "mem_percent": mem,
        }
    return None


def parse_auth_fail_ip(
    line: str,
    bin_path: str | Path | None = None,
    *,
    timeout: float = 3.0,
) -> str | None:
    """Peer IP via `guard-core auth-fail-ip --line` (None when the bin misses)."""
    exe = Path(bin_path) if bin_path else find_bin()
    if exe is None or not exe.is_file():
        return None
    try:
        proc = subprocess.run(
            [str(exe), "auth-fail-ip", "--line", line],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    ip = (proc.stdout or "").strip()
    return ip or None


def shadow_compare_metrics(
    python_row: dict[str, Any],
    rust_row: dict[str, Any],
    *,
    tol: float = 25.0,
) -> dict[str, Any]:
    """Diff Python vs guard-core CPU/mem. `agree` when both deltas stay within `tol`."""

    def _f(row: dict[str, Any], key: str) -> float:
        try:
            return float(row.get(key) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    pc, pm = _f(python_row, "cpu_percent"), _f(python_row, "mem_percent")
    rc, rm = _f(rust_row, "cpu_percent"), _f(rust_row, "mem_percent")
    cpu_delta = rc - pc
    mem_delta = rm - pm
    return {
        "ts": time.time(),
        "python": {"cpu_percent": pc, "mem_percent": pm},
        "rust": {"cpu_percent": rc, "mem_percent": rm},
        "cpu_delta": cpu_delta,
        "mem_delta": mem_delta,
        "agree": abs(cpu_delta) <= tol and abs(mem_delta) <= tol,
    }


def append_shadow_diff(path: str | Path, record: dict[str, Any]) -> None:
    """Append one shadow-compare object as JSONL."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
