"""Python bridge for guard-core metrics shadow."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.guard_core_bridge import (
    append_shadow_diff,
    find_bin,
    parse_auth_fail_ip,
    run_once_metrics,
    shadow_compare_metrics,
)


def test_shadow_compare_tolerates_small_delta() -> None:
    diff = shadow_compare_metrics(
        {"cpu_percent": 10.0, "mem_percent": 40.0},
        {"cpu_percent": 12.0, "mem_percent": 41.0},
        tol=5.0,
    )
    assert diff["agree"] is True
    assert diff["cpu_delta"] == 2.0
    assert diff["python"]["mem_percent"] == 40.0
    assert diff["rust"]["cpu_percent"] == 12.0


def test_shadow_compare_flags_large_delta() -> None:
    diff = shadow_compare_metrics(
        {"cpu_percent": 1.0, "mem_percent": 10.0},
        {"cpu_percent": 80.0, "mem_percent": 11.0},
        tol=25.0,
    )
    assert diff["agree"] is False
    assert diff["cpu_delta"] == 79.0


def test_append_shadow_diff_jsonl(tmp_path: Path) -> None:
    dest = tmp_path / "reports" / "guard_core_shadow.jsonl"
    append_shadow_diff(dest, {"ts": 1.0, "agree": True, "cpu_delta": 0.0})
    append_shadow_diff(dest, {"ts": 2.0, "error": "guard-core metrics unavailable"})
    lines = [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["agree"] is True
    assert lines[1]["error"].startswith("guard-core")


def test_find_bin_explicit(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert find_bin(missing) is None
    exe = tmp_path / "sysspectogram-guard-core"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    assert find_bin(exe) == exe.resolve()


def test_find_bin_prefers_bundled_over_path(tmp_path: Path, monkeypatch) -> None:
    import pytest
    from sysspectogram import guard_core_bridge as bridge

    root = Path(bridge.__file__).resolve().parents[1]
    bundled = None
    for rel in (
        "guard-core/target/release/sysspectogram-guard-core",
        "guard-core/target/debug/sysspectogram-guard-core",
        "bin/sysspectogram-guard-core",
    ):
        cand = root / rel
        if cand.is_file():
            bundled = cand.resolve()
            break
    if bundled is None:
        pytest.skip("no bundled guard-core binary in tree")
    fake_path = tmp_path / "sysspectogram-guard-core"
    fake_path.write_text("#!/bin/sh\necho path\n", encoding="utf-8")
    fake_path.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    found = find_bin()
    assert found is not None
    assert found.resolve() == bundled
    assert found.resolve() != fake_path.resolve()


def test_verify_bin_sha256(tmp_path: Path) -> None:
    from sysspectogram.guard_core_bridge import verify_bin_sha256
    import hashlib

    exe = tmp_path / "bin"
    exe.write_bytes(b"abc")
    digest = hashlib.sha256(b"abc").hexdigest()
    assert verify_bin_sha256(exe, None) is True
    assert verify_bin_sha256(exe, digest) is True
    assert verify_bin_sha256(exe, "0" * 64) is False


def test_bridge_matches_cli_on_doc_ip() -> None:
    root = Path(__file__).resolve().parents[1] / "guard-core"
    exe = find_bin()
    built = root / "target" / "debug" / "sysspectogram-guard-core"
    if exe is None and not built.is_file():
        import subprocess

        proc = subprocess.run(
            ["cargo", "build", "-q"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            import pytest

            pytest.fail(proc.stderr or proc.stdout or "cargo build failed")
    exe = exe or find_bin() or built
    ip = parse_auth_fail_ip(
        "Failed password for root from 203.0.113.9 port 22 ssh2",
        exe,
    )
    assert ip == "203.0.113.9"
    assert parse_auth_fail_ip("no failure here", exe) is None
    sample = run_once_metrics(exe)
    assert sample is not None
    assert "cpu_percent" in sample and "mem_percent" in sample
