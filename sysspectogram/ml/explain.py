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
    """Top features + one plain sentence for Telegram/web/CLI."""
    feats = feature_attribution(window, columns, top_k=top_k)
    band = spectrogram_band_hint(window)
    top = feats[0] if feats else None
    name = str((top or {}).get("feature") or "load")
    mean = float((top or {}).get("mean") or 0.0)
    if lang.startswith("ru"):
        guess = "майнер или сборка" if "cpu" in name else "необычная нагрузка"
        sentence = (
            f"{name} ≈ {mean:.0f} (обычно ниже): похоже на {guess}."
            + (f" Полоса: {band}." if band else "")
        )
    else:
        guess = "miner or a heavy build" if "cpu" in name else "unusual load"
        sentence = (
            f"{name} ≈ {mean:.0f} (usually lower): looks like {guess}."
            + (f" Band: {band}." if band else "")
        )
    return {
        "top_features": feats,
        "band": band,
        "sentence": sentence,
        "primary": name,
    }
