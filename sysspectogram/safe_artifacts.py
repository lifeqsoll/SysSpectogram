"""Pickle-free artifact I/O for scaler + IsolationForest (v0.9+).

Runtime inference loads only ``scaler.json`` / ``iforest.ssf.npz``.
Legacy ``.joblib`` is readable solely by ``migrate_artifacts_dir``.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import BinaryIO

import numpy as np

SCALER_JSON = "scaler.json"
SCALER_JOBLIB = "scaler.joblib"
IFOREST_SSF = "iforest.ssf.npz"
IFOREST_SSF_META = "iforest.ssf.meta.json"
IFOREST_JOBLIB = "iforest.joblib"


def _average_path_length(n_samples: np.ndarray | float) -> np.ndarray | float:
    """Match sklearn.ensemble._iforest._average_path_length."""
    n = np.asarray(n_samples, dtype=np.float64)
    out = np.zeros_like(n, dtype=np.float64)
    mask = n > 2.0
    out[mask] = 2.0 * (np.log(n[mask] - 1.0) + 0.5772156649) - 2.0 * (n[mask] - 1.0) / n[mask]
    out[n == 2.0] = 1.0
    if np.isscalar(n_samples):
        return float(out)
    return out


class SsfIsolationScorer:
    """IsolationForest-equivalent scorer rebuilt from exported tree arrays."""

    def __init__(
        self,
        *,
        children_left: list[np.ndarray],
        children_right: list[np.ndarray],
        feature: list[np.ndarray],
        threshold: list[np.ndarray],
        n_node_samples: list[np.ndarray],
        offset: float,
        max_samples: int,
        n_features: int,
    ) -> None:
        self.children_left = children_left
        self.children_right = children_right
        self.feature = feature
        self.threshold = threshold
        self.n_node_samples = n_node_samples
        self.offset_ = float(offset)
        self.max_samples_ = int(max_samples)
        self.n_features_in_ = int(n_features)
        self._avg_path = float(_average_path_length(float(self.max_samples_)))

    def decision_function(self, x: np.ndarray) -> np.ndarray:
        x = np.asarray(x, dtype=np.float64)
        if x.ndim == 1:
            x = x.reshape(1, -1)
        depths = np.zeros(x.shape[0], dtype=np.float64)
        for i in range(len(self.children_left)):
            depths += self._path_length(x, i)
        depths /= max(len(self.children_left), 1)
        scores = np.power(2.0, -depths / max(self._avg_path, 1e-12))
        # Match sklearn IsolationForest.decision_function == score_samples - offset
        # where score_samples == -scores
        return -scores - self.offset_

    def _path_length(self, x: np.ndarray, tree_i: int) -> np.ndarray:
        """Match sklearn: decision_path node count + avg_path(n_leaf) - 1."""
        left = self.children_left[tree_i]
        right = self.children_right[tree_i]
        feat = self.feature[tree_i]
        thr = self.threshold[tree_i]
        n_node = self.n_node_samples[tree_i]
        n = x.shape[0]
        node = np.zeros(n, dtype=np.int32)
        n_nodes_on_path = np.ones(n, dtype=np.float64)  # count root
        active = np.ones(n, dtype=bool)
        for _ in range(int(left.shape[0]) + 2):
            if not active.any():
                break
            idx = np.where(active)[0]
            nodes = node[idx]
            is_leaf = left[nodes] == -1
            if np.any(~is_leaf):
                internal = idx[~is_leaf]
                inodes = node[internal]
                go_left = x[internal, feat[inodes]] <= thr[inodes]
                node[internal[go_left]] = left[inodes[go_left]]
                node[internal[~go_left]] = right[inodes[~go_left]]
                n_nodes_on_path[internal] += 1.0
            # re-evaluate leaves after step
            idx = np.where(active)[0]
            nodes = node[idx]
            is_leaf = left[nodes] == -1
            if is_leaf.any():
                leaf_idx = idx[is_leaf]
                leaf_nodes = node[leaf_idx]
                depth = (
                    n_nodes_on_path[leaf_idx]
                    + _average_path_length(n_node[leaf_nodes].astype(np.float64))
                    - 1.0
                )
                # store final depth in n_nodes_on_path slot for finished rows
                n_nodes_on_path[leaf_idx] = depth
                active[leaf_idx] = False
        return n_nodes_on_path


def export_isolation_forest(model) -> tuple[dict[str, np.ndarray], dict]:
    """Serialize a fitted sklearn IsolationForest into npz arrays + meta."""
    arrays: dict[str, np.ndarray] = {}
    n_estimators = len(model.estimators_)
    for i, est in enumerate(model.estimators_):
        tree = est.tree_
        arrays[f"t{i}_children_left"] = np.asarray(tree.children_left, dtype=np.int32)
        arrays[f"t{i}_children_right"] = np.asarray(tree.children_right, dtype=np.int32)
        arrays[f"t{i}_feature"] = np.asarray(tree.feature, dtype=np.int32)
        arrays[f"t{i}_threshold"] = np.asarray(tree.threshold, dtype=np.float64)
        arrays[f"t{i}_n_node_samples"] = np.asarray(tree.n_node_samples, dtype=np.int64)
    cont = getattr(model, "contamination", 0.1)
    try:
        cont_f = float(cont)
    except (TypeError, ValueError):
        cont_f = 0.1
    meta = {
        "format": "sysspectogram.iforest.ssf",
        "version": 1,
        "n_estimators": n_estimators,
        "offset": float(model.offset_),
        "max_samples": int(model.max_samples_),
        "n_features": int(model.n_features_in_),
        "contamination": cont_f,
        "random_state": getattr(model, "random_state", None),
    }
    return arrays, meta


def load_ssf_scorer(npz_path: Path, meta_path: Path | None = None) -> SsfIsolationScorer:
    npz_path = Path(npz_path)
    meta_path = Path(meta_path) if meta_path else npz_path.with_name(IFOREST_SSF_META)
    if not meta_path.is_file():
        # allow sidecar next to custom names: foo.ssf.npz -> foo.ssf.meta.json
        alt = npz_path.with_suffix("").with_suffix(".meta.json")
        if alt.is_file():
            meta_path = alt
        else:
            raise FileNotFoundError(f"missing SSF meta: {meta_path}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("format") != "sysspectogram.iforest.ssf":
        raise RuntimeError(f"unsupported iforest SSF format: {meta.get('format')}")
    data = np.load(npz_path)
    n = int(meta["n_estimators"])
    children_left, children_right, feature, threshold, n_node_samples = [], [], [], [], []
    for i in range(n):
        children_left.append(np.asarray(data[f"t{i}_children_left"]))
        children_right.append(np.asarray(data[f"t{i}_children_right"]))
        feature.append(np.asarray(data[f"t{i}_feature"]))
        threshold.append(np.asarray(data[f"t{i}_threshold"]))
        n_node_samples.append(np.asarray(data[f"t{i}_n_node_samples"]))
    return SsfIsolationScorer(
        children_left=children_left,
        children_right=children_right,
        feature=feature,
        threshold=threshold,
        n_node_samples=n_node_samples,
        offset=float(meta["offset"]),
        max_samples=int(meta["max_samples"]),
        n_features=int(meta["n_features"]),
    )


def save_ssf(model, npz_path: Path, meta_path: Path | None = None) -> None:
    npz_path = Path(npz_path)
    meta_path = Path(meta_path) if meta_path else npz_path.with_name(IFOREST_SSF_META)
    npz_path.parent.mkdir(parents=True, exist_ok=True)
    arrays, meta = export_isolation_forest(model)
    np.savez_compressed(npz_path, **arrays)
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def scaler_to_json_payload(scaler_obj, n_features: int | None) -> dict:
    from sklearn.preprocessing import MinMaxScaler, RobustScaler

    n_feat = int(n_features) if n_features is not None else int(
        getattr(scaler_obj, "n_features_in_", 0)
    )
    if isinstance(scaler_obj, RobustScaler):
        center = getattr(scaler_obj, "center_", None)
        scale = getattr(scaler_obj, "scale_", None)
        if center is None or scale is None:
            raise RuntimeError("RobustScaler is not fitted")
        return {
            "format": "sysspectogram.scaler.json",
            "version": 1,
            "kind": "robust",
            "n_features": n_feat,
            "center": np.asarray(center, dtype=np.float64).tolist(),
            "scale": np.asarray(scale, dtype=np.float64).tolist(),
            "with_centering": bool(getattr(scaler_obj, "with_centering", True)),
            "with_scaling": bool(getattr(scaler_obj, "with_scaling", True)),
        }
    if isinstance(scaler_obj, MinMaxScaler):
        data_min = getattr(scaler_obj, "data_min_", None)
        data_max = getattr(scaler_obj, "data_max_", None)
        scale = getattr(scaler_obj, "scale_", None)
        min_ = getattr(scaler_obj, "min_", None)
        if data_min is None or data_max is None or scale is None or min_ is None:
            raise RuntimeError("MinMaxScaler is not fitted")
        fr = getattr(scaler_obj, "feature_range", (0, 1))
        return {
            "format": "sysspectogram.scaler.json",
            "version": 1,
            "kind": "minmax",
            "n_features": n_feat,
            "data_min": np.asarray(data_min, dtype=np.float64).tolist(),
            "data_max": np.asarray(data_max, dtype=np.float64).tolist(),
            "scale": np.asarray(scale, dtype=np.float64).tolist(),
            "min": np.asarray(min_, dtype=np.float64).tolist(),
            "feature_range": [float(fr[0]), float(fr[1])],
        }
    raise RuntimeError(f"unsupported scaler type for JSON export: {type(scaler_obj)}")


def scaler_from_json_payload(payload: dict):
    from sklearn.preprocessing import MinMaxScaler, RobustScaler

    if payload.get("format") != "sysspectogram.scaler.json":
        raise RuntimeError(f"unsupported scaler format: {payload.get('format')}")
    kind = str(payload.get("kind") or "robust").lower()
    n_feat = int(payload["n_features"])
    if kind == "minmax":
        fr = payload.get("feature_range") or [0.0, 1.0]
        ms = MinMaxScaler(feature_range=(float(fr[0]), float(fr[1])))
        ms.data_min_ = np.asarray(payload["data_min"], dtype=np.float64)
        ms.data_max_ = np.asarray(payload["data_max"], dtype=np.float64)
        ms.scale_ = np.asarray(payload["scale"], dtype=np.float64)
        ms.min_ = np.asarray(payload["min"], dtype=np.float64)
        ms.n_features_in_ = n_feat
        ms.n_samples_seen_ = 1
        return ms, n_feat
    # default / robust (v1 payloads omit kind)
    rs = RobustScaler(
        with_centering=bool(payload.get("with_centering", True)),
        with_scaling=bool(payload.get("with_scaling", True)),
    )
    rs.center_ = np.asarray(payload["center"], dtype=np.float64)
    rs.scale_ = np.asarray(payload["scale"], dtype=np.float64)
    rs.n_features_in_ = int(payload.get("n_features") or len(rs.center_))
    return rs, n_feat


def resolve_scaler_path(artifacts_dir: Path) -> Path:
    root = Path(artifacts_dir)
    p = root / SCALER_JSON
    if p.is_file():
        return p
    if (root / SCALER_JOBLIB).is_file():
        raise FileNotFoundError(
            f"only legacy {SCALER_JOBLIB} in {root}; "
            "python -m sysspectogram artifacts migrate --model DIR"
        )
    raise FileNotFoundError(f"no {SCALER_JSON} in {root}")


def resolve_iforest_path(artifacts_dir: Path) -> Path:
    root = Path(artifacts_dir)
    p = root / IFOREST_SSF
    if p.is_file():
        return p
    if (root / IFOREST_JOBLIB).is_file():
        raise FileNotFoundError(
            f"only legacy {IFOREST_JOBLIB} in {root}; "
            "python -m sysspectogram artifacts migrate --model DIR"
        )
    raise FileNotFoundError(f"no {IFOREST_SSF} in {root}")


def migrate_artifacts_dir(
    model_dir: Path,
    *,
    enforce: bool = False,
    delete_legacy: bool = False,
) -> dict[str, str]:
    """Convert legacy joblib scaler/iforest into safe formats in-place.

    This is the only supported joblib read path.
    """
    del enforce
    import joblib
    from sklearn.preprocessing import MinMaxScaler, RobustScaler

    from sysspectogram.ml.forest import ForestDetector
    from sysspectogram.preprocess.scaler import WindowScaler

    model_dir = Path(model_dir)
    done: dict[str, str] = {}
    joblib_scaler = model_dir / SCALER_JOBLIB
    json_scaler = model_dir / SCALER_JSON
    if joblib_scaler.is_file() and not json_scaler.is_file():
        payload = joblib.load(joblib_scaler)
        obj = WindowScaler()
        obj.scaler = payload["scaler"]
        obj.n_features = payload["n_features"]
        if not isinstance(obj.scaler, (RobustScaler, MinMaxScaler)):
            raise RuntimeError(f"unexpected scaler type in {joblib_scaler}: {type(obj.scaler)}")
        obj.save(json_scaler)
        done["scaler"] = str(json_scaler)
        if delete_legacy:
            joblib_scaler.unlink(missing_ok=True)
            done["scaler_deleted_legacy"] = str(joblib_scaler)
    elif json_scaler.is_file():
        done["scaler"] = "already_present"

    joblib_if = model_dir / IFOREST_JOBLIB
    ssf = model_dir / IFOREST_SSF
    if joblib_if.is_file() and not ssf.is_file():
        obj = ForestDetector()
        obj.model = joblib.load(joblib_if)
        obj.save(ssf)
        done["iforest"] = str(ssf)
        if delete_legacy:
            joblib_if.unlink(missing_ok=True)
            done["iforest_deleted_legacy"] = str(joblib_if)
    elif ssf.is_file():
        done["iforest"] = "already_present"
    return done


def _rehash_matches_manifest(
    artifacts_dir: Path,
    relative: str,
    *,
    manifest_name: str,
) -> None:
    """Re-check digest immediately before path-based load (TOCTOU harden)."""
    import hashlib
    import json as _json

    root = Path(artifacts_dir)
    manifest_path = root / manifest_name
    if not manifest_path.is_file():
        raise RuntimeError(f"manifest required: {manifest_path}")
    payload = _json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = payload.get("files") or []
    expect = None
    for row in rows:
        if isinstance(row, dict) and row.get("path") == relative:
            expect = str(row.get("sha256") or "")
            break
    if not expect:
        raise RuntimeError(f"artifact missing from manifest: {relative}")
    got = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if got != expect:
        raise RuntimeError(f"digest mismatch after verify for {relative}")


def load_scaler_for_artifacts(
    artifacts_dir: Path,
    *,
    enforce: bool = False,
    open_verified=None,
    manifest_name: str = "artifacts.manifest.json",
    signature_name: str = "artifacts.manifest.json.minisig",
):
    from sysspectogram.preprocess.scaler import WindowScaler

    path = resolve_scaler_path(artifacts_dir)
    if enforce and open_verified is not None:
        with open_verified(
            artifacts_dir,
            path.name,
            manifest_name=manifest_name,
            signature_name=signature_name,
        ) as fh:
            return WindowScaler.load(fh, enforce=enforce)
        # unreachable
    if enforce:
        _rehash_matches_manifest(artifacts_dir, path.name, manifest_name=manifest_name)
    return WindowScaler.load(path, enforce=enforce)


def load_forest_for_artifacts(
    artifacts_dir: Path,
    *,
    enforce: bool = False,
    open_verified=None,
    manifest_name: str = "artifacts.manifest.json",
    signature_name: str = "artifacts.manifest.json.minisig",
):
    from sysspectogram.ml.forest import ForestDetector

    path = resolve_iforest_path(artifacts_dir)
    meta_name = IFOREST_SSF_META if path.name == IFOREST_SSF else (
        path.name[: -len(".ssf.npz")] + ".ssf.meta.json"
    )
    if enforce and open_verified is not None:
        with open_verified(
            artifacts_dir,
            path.name,
            manifest_name=manifest_name,
            signature_name=signature_name,
        ):
            pass
        with open_verified(
            artifacts_dir,
            meta_name,
            manifest_name=manifest_name,
            signature_name=signature_name,
        ):
            pass
        _rehash_matches_manifest(artifacts_dir, path.name, manifest_name=manifest_name)
        _rehash_matches_manifest(artifacts_dir, meta_name, manifest_name=manifest_name)
    return ForestDetector.load(path, enforce=enforce)


def warn_legacy(path: Path) -> None:
    warnings.warn(
        f"legacy joblib path referenced ({path}); use artifacts migrate",
        UserWarning,
        stacklevel=3,
    )


def is_joblib_path(path: Path | str | BinaryIO) -> bool:
    if hasattr(path, "read"):
        return False
    p = Path(path)
    return p.suffix == ".joblib" or p.name.endswith(".joblib")
