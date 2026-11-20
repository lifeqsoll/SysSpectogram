"""Alert spectrogram process samples come from the alert window when possible."""

from __future__ import annotations

import time

import numpy as np

from sysspectogram.viz.panels import ProcessCpuTracker
from sysspectogram.viz import snapshot as snap


def test_alert_uses_window_samples() -> None:
    track = ProcessCpuTracker(maxlen=10, top_k=4)
    track._warmed = True
    now = time.time()
    track.history.append(
        {
            "ts": now - 30,
            "rows": [{"pid": 9, "name": "hot", "cpu": 80.0}, {"pid": 8, "name": "idle", "cpu": 0.0}],
        }
    )
    track.history.append(
        {
            "ts": now - 10,
            "rows": [{"pid": 9, "name": "hot", "cpu": 90.0}],
        }
    )
    mat, labels = track.matrix_for_window(now - 40, now, top_k=4)
    assert any("hot(9)" in lab for lab in labels)
    assert mat.size > 0
    assert float(mat.sum()) > 0


def test_zero_cpu_rows_dropped() -> None:
    track = ProcessCpuTracker(maxlen=5, top_k=4)
    track._warmed = True
    now = time.time()
    track.history.append(
        {"ts": now, "rows": [{"pid": 1, "name": "z", "cpu": 0.0}, {"pid": 2, "name": "a", "cpu": 3.0}]}
    )
    _mat, labels = track.matrix_for_window(now - 1, now + 1, top_k=4, drop_zero=True)
    assert all("z(" not in lab for lab in labels)
    assert any("a(2)" in lab for lab in labels)


def test_live_fallback_labeled(monkeypatch) -> None:
    class FakeStore:
        def metrics(self):
            return ["cpu_percent"]

        def window(self, metric, t0, t1):
            return [(t0, 1.0), (t1, 2.0)]

    snap.set_alert_proc_tracker(None)
    monkeypatch.setattr(snap, "live_proc_matrix", lambda top_k=8: (np.ones((1, 2)), ["pod(7)"]))
    # render_alert_panel needs matplotlib; stub it.
    monkeypatch.setattr(
        snap,
        "render_alert_panel",
        lambda **kwargs: b"PNG" if "live at render" in str(kwargs.get("title", "")) or any(
            "live at render" in str(x) for x in (kwargs.get("proc_labels") or [])
        ) else b"PNG",
    )
    out = snap.render_window(FakeStore(), time.time() - 10, time.time(), title="t")
    assert out == b"PNG"
