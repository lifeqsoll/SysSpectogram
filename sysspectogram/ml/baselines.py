"""Label-free statistical baselines for honest ML enablement (Phase 7.4).

All models fit **only on normal train** windows; threshold = quantile of
normal scores (default 0.999). Used by ``eval_offline`` and ``check_ml_ready``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np

from sysspectogram.ml.features import features_for_iforest
from sysspectogram.preprocess.scaler import WindowScaler


def _stack_feats(
    windows: list[np.ndarray],
    scaler: WindowScaler | None,
) -> np.ndarray:
    rows = [features_for_iforest(w, scaler) for w in windows]
    return np.vstack(rows).astype(np.float64)


@dataclass
class BaselineResult:
    name: str
    scores: np.ndarray
    threshold: float


def fit_project_zscore(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    quantile: float = 0.999,
) -> BaselineResult:
    x = _stack_feats(normal_train, scaler)
    mu = x.mean(axis=0)
    sigma = x.std(axis=0)
    sigma = np.where(sigma < 1e-6, 1.0, sigma)
    train_scores = np.max(np.abs((x - mu) / sigma), axis=1)
    thr = float(np.quantile(train_scores, quantile)) if train_scores.size else 3.0
    ev = _stack_feats(eval_windows, scaler)
    scores = np.max(np.abs((ev - mu) / sigma), axis=1)
    # map to [0,1]-ish for reporting parity
    scores01 = np.clip(scores / max(thr, 1e-6) * 0.5, 0.0, 1.0)
    return BaselineResult("zscore", scores01.astype(np.float64), 0.5)


def fit_robust_z(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    quantile: float = 0.999,
) -> BaselineResult:
    x = _stack_feats(normal_train, scaler)
    med = np.median(x, axis=0)
    mad = np.median(np.abs(x - med), axis=0)
    mad = np.where(mad < 1e-9, 1e-9, mad)
    train_z = np.max(np.abs((x - med) / mad), axis=1)
    thr = float(np.quantile(train_z, quantile)) if train_z.size else 3.0
    ev = _stack_feats(eval_windows, scaler)
    z = np.max(np.abs((ev - med) / mad), axis=1)
    scores01 = np.clip(z / max(thr, 1e-6) * 0.5, 0.0, 1.0)
    return BaselineResult("robust_z", scores01.astype(np.float64), 0.5)


def fit_ewma_residual(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    alpha: float = 0.2,
    quantile: float = 0.999,
) -> BaselineResult:
    x = _stack_feats(normal_train, scaler)
    mean = x.mean(axis=0)

    def _score_rows(rows: np.ndarray) -> np.ndarray:
        ewma = mean.copy()
        out = []
        for row in rows:
            ewma = alpha * row + (1.0 - alpha) * ewma
            out.append(float(np.linalg.norm(row - ewma)))
        return np.asarray(out, dtype=np.float64)

    train_s = _score_rows(x)
    thr = float(np.quantile(train_s, quantile)) if train_s.size else 1.0
    ev = _stack_feats(eval_windows, scaler)
    s = _score_rows(ev)
    scores01 = np.clip(s / max(thr, 1e-6) * 0.5, 0.0, 1.0)
    return BaselineResult("ewma", scores01.astype(np.float64), 0.5)


def fit_iforest_stats(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    quantile: float = 0.999,
    random_state: int = 42,
) -> BaselineResult:
    from sklearn.ensemble import IsolationForest

    x = _stack_feats(normal_train, scaler)
    clf = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=random_state,
    )
    clf.fit(x)
    # decision_function: higher = more normal → invert
    train_s = -clf.decision_function(x)
    thr = float(np.quantile(train_s, quantile)) if train_s.size else 0.0
    ev = _stack_feats(eval_windows, scaler)
    s = -clf.decision_function(ev)
    # threshold on raw inverted scores; report 0/1 via thr
    scores01 = (s >= thr).astype(np.float64) * 0.75 + np.clip(
        (s - thr) / (abs(thr) + 1e-6) * 0.25, 0.0, 0.25
    )
    return BaselineResult("iforest_stats", scores01.astype(np.float64), 0.5)


def fit_pca_recon(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    n_components: int = 8,
    quantile: float = 0.999,
) -> BaselineResult:
    from sklearn.decomposition import PCA

    x = _stack_feats(normal_train, scaler)
    k = max(1, min(n_components, x.shape[0] - 1, x.shape[1]))
    pca = PCA(n_components=k, random_state=42)
    pca.fit(x)

    def recon_err(rows: np.ndarray) -> np.ndarray:
        z = pca.transform(rows)
        hat = pca.inverse_transform(z)
        return np.linalg.norm(rows - hat, axis=1)

    train_s = recon_err(x)
    thr = float(np.quantile(train_s, quantile)) if train_s.size else 1.0
    ev = _stack_feats(eval_windows, scaler)
    s = recon_err(ev)
    scores01 = np.clip(s / max(thr, 1e-6) * 0.5, 0.0, 1.0)
    return BaselineResult("pca", scores01.astype(np.float64), 0.5)


BASELINE_FITTERS: dict[str, Callable[..., BaselineResult]] = {
    "zscore": fit_project_zscore,
    "robust_z": fit_robust_z,
    "ewma": fit_ewma_residual,
    "iforest_stats": fit_iforest_stats,
    "pca": fit_pca_recon,
}


def run_all_baselines(
    normal_train: list[np.ndarray],
    eval_windows: list[np.ndarray],
    *,
    scaler: WindowScaler | None = None,
    quantile: float = 0.999,
) -> list[BaselineResult]:
    out: list[BaselineResult] = []
    for name, fn in BASELINE_FITTERS.items():
        try:
            out.append(fn(normal_train, eval_windows, scaler=scaler, quantile=quantile))
        except Exception:
            continue
    return out
