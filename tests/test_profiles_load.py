from __future__ import annotations

from pathlib import Path

from sysspectogram.load_profile import apply_load_profile, PRESETS
from sysspectogram.profiles import install_profile, pack_profile
from sysspectogram.risk import fuse_host_agent
from sysspectogram.config import load_config


def test_fuse_host_agent():
    assert abs(fuse_host_agent(1.0, 0.0, host_weight=1, agent_weight=0) - 1.0) < 1e-6
    r = fuse_host_agent(1.0, 0.0, host_weight=0.5, agent_weight=0.5)
    assert abs(r - 0.5) < 1e-6


def test_load_profile_lite_vs_full():
    lite = apply_load_profile({"load_profile": "lite"})
    full = apply_load_profile({"load_profile": "full"})
    assert lite["collector"]["interval_sec"] >= full["collector"]["interval_sec"]
    assert lite["agent"]["max_alerts_per_min"] < full["agent"]["max_alerts_per_min"]
    assert full["flow"]["enabled"] is True
    assert lite["flow"]["enabled"] is False
    assert "lite" in PRESETS and "full" in PRESETS


def test_default_config_applies_lite():
    cfg = load_config()
    assert cfg.get("load_profile") == "lite"
    assert cfg["collector"]["interval_sec"] == 2.0


def test_profile_pack_install_roundtrip(tmp_path: Path):
    host = tmp_path / "host"
    host.mkdir()
    (host / "meta.json").write_text('{"threshold": 0.5, "columns": ["cpu_percent"]}\n', encoding="utf-8")
    (host / "dummy.bin").write_bytes(b"x")
    tar = tmp_path / "profile-test.tar.gz"
    meta = pack_profile(
        name="profile-test",
        role="generic-linux",
        host_artifacts=host,
        out_tar=tar,
    )
    assert tar.exists()
    assert meta["sha256"]
    dest = tmp_path / "installed"
    info = install_profile(tar, dest, expected_sha256=meta["sha256"])
    assert Path(info["host"]).is_dir()
    assert (Path(info["host"]) / "meta.json").exists()


def test_install_requires_sha256(tmp_path: Path):
    host = tmp_path / "host"
    host.mkdir()
    (host / "meta.json").write_text('{"threshold": 0.5}\n', encoding="utf-8")
    tar = tmp_path / "p.tar.gz"
    pack_profile(name="p", role="generic-linux", host_artifacts=host, out_tar=tar)
    try:
        install_profile(tar, tmp_path / "x")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "sha256" in str(e).lower()
