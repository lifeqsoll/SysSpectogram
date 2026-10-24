from __future__ import annotations

from pathlib import Path

from sysspectogram.remote_devices import (
    begin_pair,
    complete_pair,
    devices_configured,
    list_devices,
    revoke_all,
    revoke_device,
    verify_token,
)


def test_pair_roundtrip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    started = begin_pair(label="laptop", root=tmp_path)
    assert started["ok"] and started["pair_code"]
    bad = complete_pair("AAAAAAAAAA", root=tmp_path)
    assert not bad["ok"]
    done = complete_pair(started["pair_code"], label="laptop", root=tmp_path)
    assert done["ok"] and done["device_token"] and done["device_id"]
    assert devices_configured(tmp_path)
    assert verify_token(done["device_token"], root=tmp_path) is not None
    assert verify_token("nope", root=tmp_path) is None
    # code single-use
    again = complete_pair(started["pair_code"], root=tmp_path)
    assert not again["ok"]
    rows = list_devices(tmp_path)
    assert len(rows) == 1 and rows[0].label == "laptop"
    assert revoke_device(done["device_id"], root=tmp_path)["ok"]
    assert not devices_configured(tmp_path)
    revoke_all(root=tmp_path)


def test_pair_expiry(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    started = begin_pair(ttl_sec=0.01, root=tmp_path)
    import time

    time.sleep(0.05)
    assert not complete_pair(started["pair_code"], root=tmp_path)["ok"]
