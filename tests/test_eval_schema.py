import json
from pathlib import Path

from sysspectogram.ml.eval_report import CURRENT_SCHEMA_VERSION, ensure_schema_version, read_artifact_schema


def test_stamp_schema_version(tmp_path: Path):
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"threshold": 0.5}), encoding="utf-8")
    before = read_artifact_schema(tmp_path)
    assert before["schema_version"] is None
    out = ensure_schema_version(tmp_path)
    assert out["ok"] and out["changed"]
    after = read_artifact_schema(tmp_path)
    assert after["schema_version"] == CURRENT_SCHEMA_VERSION
    assert after["windows_format"] == "raw"
