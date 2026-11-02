"""Phase 7.5 — false alerts/day and TTD on synthetic timeline."""

from __future__ import annotations

import numpy as np

from sysspectogram.ml.user_metrics import Episode, false_alerts_per_day, time_to_detect


def test_false_alerts_cooldown_and_ttd() -> None:
    # 100 windows, stride 5s → 500s span
    y = np.zeros(100, dtype=np.int32)
    pred = np.zeros(100, dtype=np.int32)
    # FP at 10, 11, 12 (cooldown 60s → stride 5 → 12 windows) → one episode
    pred[10] = pred[11] = pred[12] = 1
    pred[40] = 1  # second FP after cooldown
    rate = false_alerts_per_day(y, pred, window_stride_sec=5.0, cooldown_sec=60.0)
    assert rate > 0
    # two episodes in 500s → 2 * 86400/500 = 345.6 /day
    assert abs(rate - 2 * (86400.0 / 500.0)) < 1.0

    y2 = np.zeros(50, dtype=np.int32)
    pred2 = np.zeros(50, dtype=np.int32)
    y2[10:30] = 1
    pred2[15] = 1  # detect 5 windows after start → 25s
    ttd = time_to_detect(
        y2,
        pred2,
        window_stride_sec=5.0,
        episodes=[Episode(10, 30, "miner")],
    )
    assert ttd["miner"] == 25.0
