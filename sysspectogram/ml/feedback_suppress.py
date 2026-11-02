"""Suppress similar host-ML alerts after operator marks «this is normal» (Phase 7.7)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from sysspectogram.config import state_root
from sysspectogram.ml.features import features_for_iforest
from sysspectogram.preprocess.scaler import WindowScaler


def _path() -> Path:
    return state_root() / "state" / "ml_fp_suppress.json"


def load() -> dict[str, Any]:
    p = _path()
    if not p.is_file():
        return {"prototypes": [], "undo": None, "fp_count": 0}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"prototypes": [], "undo": None, "fp_count": 0}
    except (OSError, ValueError):
        return {"prototypes": [], "undo": None, "fp_count": 0}


def save(data: dict[str, Any]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def mark_normal(
    window: np.ndarray,
    *,
    scaler: WindowScaler | None = None,
    max_prototypes: int = 32,
) -> dict[str, Any]:
    """Record FP window as a suppress prototype; schedule refit separately."""
    vec = features_for_iforest(window, scaler).astype(np.float64)
    data = load()
    proto = {"vec": vec.tolist(), "ts": time.time()}
    data.setdefault("prototypes", []).append(proto)
    data["prototypes"] = data["prototypes"][-max_prototypes:]
    data["undo"] = {"action": "mark_normal", "proto": proto}
    data["fp_count"] = int(data.get("fp_count") or 0) + 1
    data["refit_pending"] = True
    save(data)
    return {"ok": True, "fp_count": data["fp_count"], "n_prototypes": len(data["prototypes"])}


def undo_last() -> dict[str, Any]:
    data = load()
    undo = data.get("undo")
    if not undo:
        return {"ok": False, "detail": "nothing to undo"}
    proto = undo.get("proto")
    protos = data.get("prototypes") or []
    if proto and protos and protos[-1].get("ts") == proto.get("ts"):
        protos.pop()
        data["fp_count"] = max(0, int(data.get("fp_count") or 0) - 1)
    data["prototypes"] = protos
    data["undo"] = None
    save(data)
    return {"ok": True, "fp_count": data["fp_count"]}


def should_suppress(
    window: np.ndarray,
    *,
    scaler: WindowScaler | None = None,
    cosine_thresh: float = 0.97,
) -> bool:
    data = load()
    protos = data.get("prototypes") or []
    if not protos:
        return False
    vec = features_for_iforest(window, scaler).astype(np.float64)
    nrm = float(np.linalg.norm(vec)) + 1e-9
    for p in protos:
        pv = np.asarray(p.get("vec") or [], dtype=np.float64)
        if pv.shape != vec.shape:
            continue
        sim = float(np.dot(vec, pv) / (nrm * (float(np.linalg.norm(pv)) + 1e-9)))
        if sim >= cosine_thresh:
            return True
    return False
