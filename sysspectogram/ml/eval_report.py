"""Offline eval report + schema_version helpers (wraps scripts/eval_offline logic lightly)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


CURRENT_SCHEMA_VERSION = 2


def read_artifact_schema(model_dir: Path) -> dict[str, Any]:
    meta_path = Path(model_dir) / "meta.json"
    if not meta_path.is_file():
        return {"ok": False, "error": "meta.json missing", "schema_version": None}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc), "schema_version": None}
    ver = meta.get("schema_version")
    if ver is None:
        ver = meta.get("dataset_schema_version")
    return {
        "ok": True,
        "schema_version": ver,
        "windows_format": meta.get("windows_format"),
        "path": str(meta_path),
        "current": CURRENT_SCHEMA_VERSION,
        "compatible": int(ver or 0) >= CURRENT_SCHEMA_VERSION
        or str(meta.get("windows_format") or "") == "raw",
    }


def ensure_schema_version(model_dir: Path, *, schema_version: int = CURRENT_SCHEMA_VERSION) -> dict[str, Any]:
    """Write schema_version into meta.json if missing (does not rewrite windows)."""
    meta_path = Path(model_dir) / "meta.json"
    if not meta_path.is_file():
        return {"ok": False, "error": "meta.json missing"}
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    changed = False
    if meta.get("schema_version") != schema_version:
        meta["schema_version"] = schema_version
        changed = True
    if not meta.get("windows_format"):
        meta["windows_format"] = "raw"
        changed = True
    if changed:
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "changed": changed, "schema_version": meta.get("schema_version"), "meta": meta}


def run_eval(
    *,
    dataset: Path,
    model: Path,
    out: Path,
    methods: str = "fuse,cnn,iforest,zscore",
    runtime: str = "onnx",
) -> dict[str, Any]:
    """Invoke scripts/eval_offline.py and return paths + parsed metrics if present."""
    root = Path(__file__).resolve().parents[2]
    script = root / "scripts" / "eval_offline.py"
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(script),
        "--dataset",
        str(dataset),
        "--model",
        str(model),
        "--methods",
        methods,
        "--runtime",
        runtime,
        "--out",
        str(out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    metrics_path = out / "metrics.json"
    metrics = None
    if metrics_path.is_file():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metrics = None
    schema = read_artifact_schema(Path(model))
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-2000:],
        "stderr": (proc.stderr or "")[-2000:],
        "metrics_json": str(metrics_path) if metrics_path.is_file() else None,
        "metrics_md": str(out / "metrics.md") if (out / "metrics.md").is_file() else None,
        "metrics": metrics,
        "model_schema": schema,
    }
