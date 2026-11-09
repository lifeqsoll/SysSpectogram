"""home settings type/range validation + corrupt refuse + flocked writes."""

from __future__ import annotations

import json
import threading
from argparse import Namespace

import pytest


def test_home_settings_rejects_bad_types(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    path = tmp_path / "state" / "user-settings.json"
    path.write_text('{"ui.lang": "en"}\n', encoding="utf-8")
    before = path.read_text(encoding="utf-8")

    from sysspectogram.cli import _cmd_home_settings

    cases = [
        '{"monitor.interval_sec":"x"}',
        '{"ensemble.risk_threshold":-5}',
        '{"web.enabled":"maybe"}',
        '{"ui.lang":"../../etc"}',
        '{"kirk.vmi_backend":"$(id)"}',
    ]
    for raw in cases:
        rc = _cmd_home_settings(Namespace(changes=raw, no_rollback=True, force=False))
        assert rc == 2, raw
        assert path.read_text(encoding="utf-8") == before


def test_home_settings_rejects_infinity(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    path = tmp_path / "state" / "user-settings.json"
    path.write_text("{}\n", encoding="utf-8")

    from sysspectogram.cli import _cmd_home_settings

    # 1e309 → Infinity in Python json
    rc = _cmd_home_settings(
        Namespace(changes='{"ensemble.risk_threshold":1e309}', no_rollback=True, force=False)
    )
    assert rc == 2
    assert path.read_text(encoding="utf-8") == "{}\n"


def test_home_settings_corrupt_refuses(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    path = tmp_path / "state" / "user-settings.json"
    path.write_text(
        '{"response.never_ban_cidrs":"203.0.113.10/32","ui.lang":"ru",}\n',
        encoding="utf-8",
    )
    before = path.read_text(encoding="utf-8")

    from sysspectogram.cli import _cmd_home_settings

    rc = _cmd_home_settings(
        Namespace(changes='{"ui.lang":"en"}', no_rollback=True, force=False)
    )
    assert rc == 2
    assert path.read_text(encoding="utf-8") == before
    assert "203.0.113.10" in before


def test_overlay_skips_bad_interval(tmp_path, monkeypatch, caplog):
    import logging

    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir()
    (state / "user-settings.json").write_text(
        '{"monitor.interval_sec":"x"}\n', encoding="utf-8"
    )
    import sysspectogram.config as config_mod

    monkeypatch.setattr(config_mod, "_apply_settings_overlay", lambda data: data)
    with caplog.at_level(logging.WARNING):
        cfg = config_mod.load_config()
    assert cfg["monitor"]["interval_sec"] != "x"
    assert any("interval_sec" in r.message for r in caplog.records)


def test_parallel_seed_never_ban_keeps_all(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()

    from sysspectogram.admin_ip import seed_never_ban

    ips = [f"203.0.113.{i}" for i in range(1, 13)]
    errors: list[str] = []

    def _one(ip: str) -> None:
        out = seed_never_ban(write=True, ip=ip)
        if not out.get("ok"):
            errors.append(f"{ip}:{out}")

    threads = [threading.Thread(target=_one, args=(ip,)) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    data = json.loads((tmp_path / "state" / "user-settings.json").read_text(encoding="utf-8"))
    raw = data.get("response.never_ban_cidrs") or ""
    for ip in ips:
        assert f"{ip}/32" in raw or ip in raw
