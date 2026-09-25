from pathlib import Path

import pytest

from sysspectogram.data_bridge import create_data_bundle, unpack_data_bundle


def test_data_bundle_roundtrip(tmp_path: Path):
    csv = tmp_path / "normal.csv"
    csv.write_text("cpu_percent\n1.0\n2.0\n", encoding="utf-8")
    out = tmp_path / "b.tgz"
    meta = create_data_bundle([csv], out, note="test")
    assert Path(meta["path"]).exists()
    dest = tmp_path / "out"
    info = unpack_data_bundle(out, dest)
    assert Path(info["csv_dir"]).exists()
    assert (Path(info["csv_dir"]) / "normal.csv").exists()


def test_data_bundle_rejects_env(tmp_path: Path):
    bad = tmp_path / ".env"
    bad.write_text("SECRET=1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="secret"):
        create_data_bundle([bad], tmp_path / "x.tgz")


def test_push_artifacts_rejects_unsafe_remote():
    from sysspectogram.data_bridge import _validate_remote_path, _validate_unit

    with pytest.raises(ValueError, match="unsafe"):
        _validate_remote_path("/tmp/x; rm -rf /")
    with pytest.raises(ValueError, match="unsafe"):
        _validate_unit("evil.service; reboot")
    assert _validate_remote_path("/opt/sysspectogram/artifacts/live") == "/opt/sysspectogram/artifacts/live"
    assert _validate_unit("sysspectogram-guard.service") == "sysspectogram-guard.service"
