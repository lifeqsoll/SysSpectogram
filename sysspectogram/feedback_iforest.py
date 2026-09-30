"""VPS-safe IsolationForest refit from operator feedback windows (opt-in)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from sysspectogram.preprocess.heatmap import tabular_features


def windows_to_tabular(windows: list[np.ndarray]) -> np.ndarray:
    rows = []
    for w in windows:
        arr = np.asarray(w, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.ndim == 3:
            # (1, H, W) spectrogram-ish — flatten time x feat if needed
            arr = arr.reshape(arr.shape[0], -1) if arr.shape[0] > 1 else arr.reshape(arr.shape[1], arr.shape[2])
        if arr.ndim != 2:
            continue
        rows.append(tabular_features(arr))
    if not rows:
        return np.zeros((0, 1), dtype=np.float32)
    return np.stack(rows).astype(np.float32)


def _load_feedback_windows(feedback_dir: Path) -> tuple[list[np.ndarray], list[np.ndarray]]:
    normal: list[np.ndarray] = []
    anomaly: list[np.ndarray] = []
    n_dir = feedback_dir / "normal"
    a_dir = feedback_dir / "anomaly"
    if n_dir.exists():
        for p in sorted(n_dir.glob("*.npy")):
            try:
                normal.append(np.load(p))
            except OSError:
                continue
    if a_dir.exists():
        for p in sorted(a_dir.glob("*.npy")):
            try:
                anomaly.append(np.load(p))
            except OSError:
                continue
    return normal, anomaly


def _update_checksums(model_dir: Path, names: list[str]) -> None:
    lines = []
    for name in names:
        f = model_dir / name
        if f.exists():
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {name}")
    if lines:
        (model_dir / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
        from sysspectogram.supply_chain import write_manifest

        write_manifest(model_dir)


def refit_host_iforest(
    model_dir: Path,
    feedback_dir: Path,
    *,
    max_rows: int = 400,
    bootstrap_path: Path | None = None,
    supply_chain: dict[str, Any] | None = None,
    minisign_secret_key: Path | None = None,
) -> dict[str, Any]:
    """Refit iforest.ssf.npz from normal feedback windows (+ optional bootstrap).

    CNN / ONNX artifacts are left untouched.
    """
    from sysspectogram.ml.forest import ForestDetector

    t0 = time.time()
    model_dir = Path(model_dir)
    feedback_dir = Path(feedback_dir)
    policy = dict(supply_chain or {})
    enforce = bool(policy.get("enforce", False))
    manifest_name = str(policy.get("manifest_name") or "artifacts.manifest.json")
    signature_name = str(
        policy.get("signature_name") or "artifacts.manifest.json.minisig"
    )
    signature_path = model_dir / signature_name
    if enforce and minisign_secret_key is None:
        raise RuntimeError(
            "enforced model refit requires --minisign-secret-key to re-sign the manifest"
        )
    iforest_path = model_dir / "iforest.ssf.npz"
    legacy = model_dir / "iforest.joblib"
    if not iforest_path.exists() and not legacy.exists():
        raise FileNotFoundError(f"missing iforest artifact under {model_dir}")

    normal_w, anomaly_w = _load_feedback_windows(feedback_dir)
    if len(normal_w) < 2:
        raise RuntimeError(
            f"need >=2 normal .npy under {feedback_dir}/normal (got {len(normal_w)})"
        )

    tab_n = windows_to_tabular(normal_w)
    if tab_n.shape[0] == 0:
        raise RuntimeError("could not extract tabular features from normal windows")

    bootstrap_path = bootstrap_path or (feedback_dir / "if_bootstrap.npz")
    if bootstrap_path.exists():
        try:
            boot = np.load(bootstrap_path)
            bx = boot["x"]
            if bx.ndim == 2 and bx.shape[1] == tab_n.shape[1]:
                tab_n = np.vstack([bx, tab_n])
        except (OSError, KeyError, ValueError):
            pass

    if tab_n.shape[0] > max_rows:
        tab_n = tab_n[-max_rows:]

    # Persist bootstrap for next runs (last normals)
    try:
        bootstrap_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(bootstrap_path, x=tab_n.astype(np.float32))
    except OSError:
        pass

    meta: dict[str, Any] = {}
    meta_path = model_dir / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}

    contamination = float(meta.get("iforest_contamination") or 0.05)
    forest = ForestDetector(contamination=contamination, random_state=42)
    forest.fit(tab_n)
    forest.save(iforest_path)

    meta["iforest_refit"] = {
        "ts": time.time(),
        "n_normal": int(tab_n.shape[0]),
        "n_anomaly_labeled": len(anomaly_w),
        "elapsed_sec": round(time.time() - t0, 3),
        "source": "feedback_iforest",
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    _update_checksums(
        model_dir,
        [
            "cnn.pt",
            "cnn.onnx",
            "iforest.ssf.npz",
            "iforest.ssf.meta.json",
            "iforest.joblib",
            "scaler.json",
            "scaler.joblib",
            "meta.json",
        ],
    )
    from sysspectogram.supply_chain import sign_file, write_manifest

    manifest_path = write_manifest(
        model_dir,
        manifest_name=manifest_name,
        signature_name=signature_name,
    )
    resigned = False
    if minisign_secret_key is not None:
        sign_file(manifest_path, Path(minisign_secret_key), signature_path=signature_path)
        resigned = True
    elif signature_path.exists():
        signature_path.unlink()

    return {
        "ok": True,
        "path": str(iforest_path),
        "n_normal": int(tab_n.shape[0]),
        "n_anomaly_labeled": len(anomaly_w),
        "elapsed_sec": round(time.time() - t0, 3),
        "cnn": "unchanged",
        "manifest": str(manifest_path),
        "resigned": resigned,
    }


class IForestHotReload:
    """Watch iforest artifact mtime and reload ForestDetector in place."""

    def __init__(self, model_dir: Path) -> None:
        from sysspectogram.safe_artifacts import resolve_iforest_path

        self.model_dir = Path(model_dir)
        try:
            self.path = resolve_iforest_path(self.model_dir)
        except FileNotFoundError:
            self.path = self.model_dir / "iforest.ssf.npz"
        self._mtime: float = 0.0
        self.forest = None
        self._load()

    def _load(self) -> bool:
        from sysspectogram.ml.forest import ForestDetector
        from sysspectogram.safe_artifacts import resolve_iforest_path

        try:
            self.path = resolve_iforest_path(self.model_dir)
        except FileNotFoundError:
            return False
        try:
            mtime = self.path.stat().st_mtime
            self.forest = ForestDetector.load(self.path)
            self._mtime = mtime
            return True
        except Exception:
            return False

    def maybe_reload(self) -> bool:
        from sysspectogram.safe_artifacts import resolve_iforest_path

        try:
            self.path = resolve_iforest_path(self.model_dir)
        except FileNotFoundError:
            return False
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        if mtime <= self._mtime:
            return False
        return self._load()
