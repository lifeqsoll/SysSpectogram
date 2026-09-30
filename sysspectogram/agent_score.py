"""Lightweight Isolation Forest scoring over agent event windows (v3 Phase 3)."""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import numpy as np

from sysspectogram.safe_artifacts import load_ssf_scorer, save_ssf

FEATURE_NAMES = (
    "open_sensitive",
    "path_watch",
    "exec_burst",
    "connect_burst",
    "module_load",
    "risky_comm",
    "unique_paths",
    "ebpf_execve",
    "ebpf_openat",
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
            elif rid in ("agent_module_load", "agent_kirk_module_load", "agent_kirk_module_delete"):
                counts["module_load"] += 1
            elif rid == "agent_ebpf_execve":
                counts["ebpf_execve"] += 1
            elif rid == "agent_ebpf_openat":
                counts["ebpf_openat"] += 1
            if risky:
                counts["risky_comm"] += 1
            if path and _path_counts_toward_score(path):
                paths.add(path)
        counts["unique_paths"] = float(len(paths))
        return np.array([counts[k] for k in FEATURE_NAMES], dtype=np.float64)


def _path_counts_toward_score(path: str) -> bool:
    p = path.lower()
    if not p or p.startswith("/proc/") or p.startswith("/sys/"):
        return False
    if "/.mount_" in p or p.startswith("/tmp/.mount_"):
        return False
    if p.endswith(".so") or ".so." in p:
        return False
    markers = (
        "/.ssh/",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/tmp/",
        "/dev/shm/",
        "/var/tmp/",
    )
    return any(m in p for m in markers)


def _agent_ssf_paths(model_path: Path) -> tuple[Path, Path]:
    path = Path(model_path)
    if path.name.endswith(".ssf.npz"):
        stem = path.name[: -len(".ssf.npz")]
        return path, path.with_name(stem + ".ssf.meta.json")
    if path.suffix == ".joblib":
        ssf = path.with_name(path.stem + ".ssf.npz")
        return ssf, path.with_name(path.stem + ".ssf.meta.json")
    ssf = path if path.suffix == ".npz" else path.with_suffix(".ssf.npz")
    if not str(ssf).endswith(".ssf.npz"):
        ssf = path.with_name(path.name + ".ssf.npz")
    stem = ssf.name[: -len(".ssf.npz")]
    return ssf, ssf.with_name(stem + ".ssf.meta.json")


class AgentIsolationScorer:
    """Optional IF model; without artifacts uses a simple heuristic score in [0,1]."""

    def __init__(
        self,
        model_path: Path | None = None,
        *,
        supply_chain: Mapping[str, Any] | None = None,
    ) -> None:
        self.model = None
        self.meta: dict[str, Any] = {}
        if not model_path:
            return
        path = Path(model_path)
        ssf, meta_path = _agent_ssf_paths(path)
        # Prefer safe SSF next to legacy joblib name
        load_path = ssf if ssf.is_file() else path
        if load_path.suffix == ".joblib" or str(load_path).endswith(".joblib"):
            raise RuntimeError(
                f"legacy agent IF joblib refused ({load_path}); re-train with "
                "train-agent-if (writes .ssf.npz) or migrate"
            )
        if not load_path.is_file():
            return
        policy = dict(supply_chain or {})
        enforce = bool(policy.get("enforce", False))
        signature_path = Path(f"{load_path}.minisig")
        verified = False
        if enforce or signature_path.exists():
            from sysspectogram.supply_chain import verify_file

            public_key = policy.get("public_key")
            if not public_key:
                raise RuntimeError(
                    "public key required for enforced agent IF signature verification"
                )
            verify_file(load_path, public_key, signature_path=signature_path)
            if meta_path.is_file():
                meta_sig = Path(f"{meta_path}.minisig")
                verify_file(meta_path, public_key, signature_path=meta_sig)
            verified = True
        try:
            self.model = load_ssf_scorer(load_path, meta_path if meta_path.is_file() else None)
            if meta_path.is_file():
                self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            # Under enforce / after signature check, do not silently fall back to heuristic.
            if enforce or verified:
                raise
            self.model = None

    def score(self, vec: np.ndarray) -> float:
        if self.model is not None:
            raw = float(-self.model.decision_function(vec.reshape(1, -1))[0])
            return float(1.0 / (1.0 + np.exp(-raw)))
        weights = np.array(
            [2.0, 1.0, 2.0, 2.0, 3.0, 1.5, 0.5, 0.15, 0.25], dtype=np.float64
        )
        if vec.shape[0] != weights.shape[0]:
            total = float(vec.sum())
            return float(min(1.0, total / 16.0))
        weighted = float(np.dot(vec, weights))
        return float(min(1.0, weighted / 12.0))


def train_agent_iforest(
    jsonl_paths: list[Path],
    out_path: Path,
    *,
    window_sec: float = 120.0,
    contamination: float = 0.05,
) -> dict[str, Any]:
    """Fit IsolationForest on sliding windows extracted from agent JSONL (mostly normal)."""
    from sklearn.ensemble import IsolationForest

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
        rng = np.random.default_rng(42)
        windows = [rng.poisson(0.3, size=len(FEATURE_NAMES)).astype(np.float64) for _ in range(64)]

    x = np.vstack(windows)
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    model.fit(x)
    out_path = Path(out_path)
    if out_path.suffix == ".joblib":
        out_path = out_path.with_name(out_path.stem + ".ssf.npz")
    if not str(out_path).endswith(".ssf.npz"):
        out_path = out_path.with_suffix(".ssf.npz")
    ssf, meta_path = _agent_ssf_paths(out_path)
    save_ssf(model, ssf, meta_path)
    # enrich meta with agent feature names
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta.update(
        {
            "features": list(FEATURE_NAMES),
            "window_sec": window_sec,
            "n_samples": int(x.shape[0]),
            "contamination": contamination,
            "kind": "agent_iforest",
        }
    )
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta
