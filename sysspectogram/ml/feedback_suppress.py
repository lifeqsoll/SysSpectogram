"""Suppress similar host-ML alerts after operator marks «this is normal» (Phase 7.7).

Contract:
- ``mark_normal`` only manages suppress prototypes in ``state/ml_fp_suppress.json``.
- IsolationForest / model refit stays on the existing Telegram debounced path
  (``_maybe_refit_if``). This module does **not** queue a second hidden refit
  (no ``refit_pending`` flag).
- ``scaler`` must match between ``mark_normal`` and ``should_suppress`` (both
  None, or the same process scaler). Mixing spaces breaks cosine.
- Prototypes expire after ``PROTOTYPE_TTL_SEC`` (default 7 days).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from sysspectogram.config import state_root
from sysspectogram.ml.features import features_for_iforest
from sysspectogram.preprocess.scaler import WindowScaler

PROTOTYPE_TTL_SEC = 7 * 24 * 3600
DEFAULT_COSINE_THRESH = 0.97
MAX_PROTOTYPES = 32


def _path() -> Path:
    return state_root() / "state" / "ml_fp_suppress.json"


def _empty() -> dict[str, Any]:
    return {"prototypes": [], "undo": None, "fp_count": 0}


def _prune_prototypes(
    protos: list[Any],
    *,
    now: float,
    n_features: int | None = None,
) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    for p in protos:
        if not isinstance(p, dict):
            continue
        ts = float(p.get("ts") or 0.0)
        if now - ts > PROTOTYPE_TTL_SEC:
            continue
        vec = p.get("vec")
        if not isinstance(vec, list) or not vec:
            continue
        nf = int(p.get("n_features") or len(vec))
        if n_features is not None and nf != n_features:
            continue
        kept.append(p)
    return kept


def load(*, now: float | None = None, n_features: int | None = None) -> dict[str, Any]:
    p = _path()
    ts = float(now if now is not None else time.time())
    if not p.is_file():
        return _empty()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return _empty()
    except (OSError, ValueError):
        return _empty()
    data["prototypes"] = _prune_prototypes(
        list(data.get("prototypes") or []),
        now=ts,
        n_features=n_features,
    )
    data.setdefault("undo", None)
    data.setdefault("fp_count", 0)
    # Drop legacy unused flag if present.
    data.pop("refit_pending", None)
    return data


def save(data: dict[str, Any]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload.pop("refit_pending", None)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def mark_normal(
    window: np.ndarray,
    *,
    scaler: WindowScaler | None = None,
    max_prototypes: int = MAX_PROTOTYPES,
    now: float | None = None,
) -> dict[str, Any]:
    """Record FP window as a suppress prototype (IF refit is caller's job)."""
    ts = float(now if now is not None else time.time())
    vec = features_for_iforest(window, scaler).astype(np.float64)
    n_features = int(vec.shape[0])
    data = load(now=ts, n_features=n_features)
    proto = {
        "vec": vec.tolist(),
        "ts": ts,
        "n_features": n_features,
        "schema": "features_for_iforest.v1",
    }
    data.setdefault("prototypes", []).append(proto)
    data["prototypes"] = data["prototypes"][-max_prototypes:]
    data["undo"] = {"action": "mark_normal", "proto": proto}
    data["fp_count"] = int(data.get("fp_count") or 0) + 1
    save(data)
    return {"ok": True, "fp_count": data["fp_count"], "n_prototypes": len(data["prototypes"])}


def undo_last(*, now: float | None = None) -> dict[str, Any]:
    ts = float(now if now is not None else time.time())
    data = load(now=ts)
    undo = data.get("undo")
    if not undo:
        return {"ok": False, "detail": "nothing to undo"}
    proto = undo.get("proto")
    protos = list(data.get("prototypes") or [])
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
    cosine_thresh: float = DEFAULT_COSINE_THRESH,
    now: float | None = None,
) -> bool:
    ts = float(now if now is not None else time.time())
    vec = features_for_iforest(window, scaler).astype(np.float64)
    n_features = int(vec.shape[0])
    data = load(now=ts, n_features=n_features)
    # Persist prune so disk stays clean.
    if data.get("prototypes") is not None:
        save(data)
    protos = data.get("prototypes") or []
    if not protos:
        return False
    nrm = float(np.linalg.norm(vec)) + 1e-9
    for p in protos:
        pv = np.asarray(p.get("vec") or [], dtype=np.float64)
        if pv.shape != vec.shape:
            continue
        sim = float(np.dot(vec, pv) / (nrm * (float(np.linalg.norm(pv)) + 1e-9)))
        if sim >= cosine_thresh:
            return True
    return False
