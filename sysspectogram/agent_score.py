"""Lightweight Isolation Forest scoring over agent event windows (v3 Phase 3)."""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np


FEATURE_NAMES = (
    "open_sensitive",
    "path_watch",
    "exec_burst",
    "connect_burst",
    "module_load",
    "risky_comm",
    "unique_paths",
)


@dataclass
class AgentFeatureWindow:
    """Rolling counts over the last `window_sec` seconds."""

    window_sec: float = 120.0
    _events: deque[tuple[float, str, bool, str]] = field(default_factory=deque)

    def push(self, rule_id: str, *, risky_comm: bool = False, path: str | None = None) -> None:
        now = time.time()
        self._events.append((now, rule_id, risky_comm, path or ""))
        self._trim(now)

    def _trim(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self.window_sec:
            self._events.popleft()

    def vector(self) -> np.ndarray:
        now = time.time()
        self._trim(now)
        counts = {k: 0.0 for k in FEATURE_NAMES}
        paths: set[str] = set()
        for _, rid, risky, path in self._events:
            if rid == "agent_open_sensitive":
                counts["open_sensitive"] += 1
            elif rid == "agent_path_watch":
                counts["path_watch"] += 1
            elif rid == "agent_exec_burst":
                counts["exec_burst"] += 1
            elif rid == "agent_connect_burst":
                counts["connect_burst"] += 1
            elif rid == "agent_module_load":
                counts["module_load"] += 1
            if risky:
                counts["risky_comm"] += 1
            if path:
                paths.add(path)
        counts["unique_paths"] = float(len(paths))
        return np.array([counts[k] for k in FEATURE_NAMES], dtype=np.float64)


class AgentIsolationScorer:
    """Optional IF model; without artifacts uses a simple heuristic score in [0,1]."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.model = None
        self.meta: dict[str, Any] = {}
        if model_path and model_path.exists():
            try:
                import joblib

                blob = joblib.load(model_path)
                self.model = blob.get("model")
                self.meta = blob.get("meta") or {}
            except Exception:
                self.model = None

    def score(self, vec: np.ndarray) -> float:
        if self.model is not None:
            # sklearn IF: decision_function higher = more normal; invert to anomaly [0,1]
            raw = float(-self.model.decision_function(vec.reshape(1, -1))[0])
            # squash
            return float(1.0 / (1.0 + np.exp(-raw)))
        # heuristic: more events → higher score
        total = float(vec.sum())
        return float(min(1.0, total / 8.0))


def train_agent_iforest(
    jsonl_paths: list[Path],
    out_path: Path,
    *,
    window_sec: float = 120.0,
    contamination: float = 0.05,
) -> dict[str, Any]:
    """Fit IsolationForest on sliding windows extracted from agent JSONL (mostly normal)."""
    from sklearn.ensemble import IsolationForest
    import joblib

    windows: list[np.ndarray] = []
    for path in jsonl_paths:
        if not path.exists():
            continue
        buf = AgentFeatureWindow(window_sec=window_sec)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("kind") == "metrics":
                continue
            rid = str(obj.get("rule_id") or "")
            extras = obj.get("extras") or {}
            buf.push(rid, risky_comm=bool(extras.get("risky_comm")), path=obj.get("path"))
            windows.append(buf.vector().copy())
    if len(windows) < 10:
        # synthesize mild normal noise so trainers don't fail on empty lab
        rng = np.random.default_rng(42)
        windows = [rng.poisson(0.3, size=len(FEATURE_NAMES)).astype(np.float64) for _ in range(64)]

    x = np.vstack(windows)
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    model.fit(x)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "features": list(FEATURE_NAMES),
        "window_sec": window_sec,
        "n_samples": int(x.shape[0]),
        "contamination": contamination,
    }
    joblib.dump({"model": model, "meta": meta}, out_path)
    return meta
