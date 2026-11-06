"""Phase 7.5 — false alerts/day and TTD on synthetic timeline."""

from __future__ import annotations

import numpy as np

from sysspectogram.ml.user_metrics import (
    Episode,
    false_alerts_per_day,
    summarize_user_metrics,
    time_to_detect,
)


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
    assert ttd["episodes"][0]["time_to_detect_sec"] == 25.0


def test_two_anomaly_episodes_both_visible() -> None:
    # Two separated anomaly blobs; first caught at +3 windows, second missed.
    y = np.zeros(80, dtype=np.int32)
    pred = np.zeros(80, dtype=np.int32)
    y[10:20] = 1
    y[50:60] = 1
    pred[13] = 1  # TTD = 3 * 5s = 15s
    # second episode: no TP
    ttd = time_to_detect(y, pred, window_stride_sec=5.0)
    eps = ttd["episodes"]
    assert len(eps) == 2
    assert eps[0]["time_to_detect_sec"] == 15.0
    assert eps[1]["time_to_detect_sec"] is None
    assert ttd["missed_episodes"] == 1
    assert ttd["time_to_detect_sec_mean"] == 15.0
    # uniquified keys both present
    assert "anomaly" in ttd
    assert "anomaly#2" in ttd
    assert ttd["anomaly"] == 15.0
    assert ttd["anomaly#2"] is None

    summary = summarize_user_metrics(y, pred, window_stride_sec=5.0)
    assert summary["missed_episodes"] == 1
    assert len(summary["time_to_detect_episodes"]) == 2
    assert isinstance(summary["time_to_detect_sec"], dict)
    assert summary["time_to_detect_sec"]["mean"] == 15.0
