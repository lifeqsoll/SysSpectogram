"""Plain-language ML alert explanation (Phase 7.6)."""

from __future__ import annotations

from typing import Any

import numpy as np

from sysspectogram.ml.calibration import feature_attribution


def spectrogram_band_hint(window: np.ndarray, sample_hz: float = 1.0) -> str | None:
    """Rough dominant period from the strongest feature's autocorr peak."""
    arr = np.asarray(window, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[0] < 8:
        return None
    col = arr[:, int(np.argmax(arr.std(axis=0)))]
    col = col - col.mean()
    if float(np.std(col)) < 1e-9:
        return None
    # cheap lag-1..N/3 energy
    best_lag, best = 1, -1.0
    max_lag = max(2, arr.shape[0] // 3)
    for lag in range(1, max_lag + 1):
        a, b = col[:-lag], col[lag:]
        corr = float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))
        if corr > best:
            best, best_lag = corr, lag
    if best < 0.3:
        return None
    period_s = best_lag / max(sample_hz, 1e-6)
    return f"~{period_s:.0f}s rhythm"


def plain_ml_line(
    window: np.ndarray,
    columns: list[str],
    *,
    lang: str = "en",
    top_k: int = 3,
) -> dict[str, Any]:
    """Top features + one observational sentence (no attack diagnosis)."""
    feats = feature_attribution(window, columns, top_k=top_k)
    band = spectrogram_band_hint(window)
    top = feats[0] if feats else None
    name = str((top or {}).get("feature") or "load")
    mean = float((top or {}).get("mean") or 0.0)
    if lang.startswith("ru"):
        sentence = f"сильнее обычного выделяется `{name}` ≈ {mean:.0f}"
        if band:
            sentence += f"; ритм {band}"
        sentence += "."
    else:
        sentence = f"`{name}` ≈ {mean:.0f} stands out vs usual"
        if band:
            sentence += f"; band {band}"
        sentence += "."
    return {
        "top_features": feats,
        "band": band,
        "sentence": sentence,
        "primary": name,
        "method": "stats",
    }


def model_based_explain(
    inferencer: Any,
    window: np.ndarray,
    columns: list[str],
    *,
    lang: str = "en",
    top_k: int = 3,
) -> dict[str, Any] | None:
    """Occlusion deltas vs the live model score (feature contribution)."""
    if inferencer is None or not hasattr(inferencer, "predict_window"):
        return None
    arr = np.asarray(window, dtype=np.float64)
    if arr.ndim != 2 or arr.shape[1] == 0 or not columns:
        return None
    try:
        base = float(inferencer.predict_window(arr).score)
    except Exception:
        return None
    deltas: list[dict[str, Any]] = []
    n_cols = min(arr.shape[1], len(columns))
    for i in range(n_cols):
        muted = arr.copy()
        muted[:, i] = 0.0
        try:
            score = float(inferencer.predict_window(muted).score)
        except Exception:
            continue
        deltas.append(
            {
                "feature": columns[i],
                "delta": abs(base - score),
                "mean": float(arr[:, i].mean()),
                "contribution": float(base - score),
            }
        )
    if not deltas:
        return None
    deltas.sort(key=lambda d: float(d["delta"]), reverse=True)
    top = deltas[: max(1, top_k)]
    name = str(top[0].get("feature") or "load")
    contrib = float(top[0].get("contribution") or 0.0)
    if lang.startswith("ru"):
        sentence = (
            f"модель сильнее всего опирается на `{name}` "
            f"(Δscore={contrib:+.3f} при занулении)."
        )
    else:
        sentence = (
            f"model leans on `{name}` most "
            f"(Δscore={contrib:+.3f} when zeroed)."
        )
    return {
        "top_features": top,
        "band": spectrogram_band_hint(arr),
        "sentence": sentence,
        "primary": name,
        "method": "model_occlusion",
        "base_score": base,
    }
