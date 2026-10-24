from __future__ import annotations

from sysspectogram.viz.tg_charts import (
    ALL_KEYS,
    build_chart_pngs,
    build_rolling_gif,
    frames_to_gif,
    render_line_chart,
    render_multi_chart,
)


def test_render_line_and_multi_includes_gpu_disk():
    series = {
        "cpu": [10.0, 20.0, 30.0, 25.0, 40.0],
        "mem": [50.0, 51.0, 52.0, 53.0, 54.0],
        "net": [100.0, 200.0, 150.0, 180.0, 90.0],
        "gpu": [0.0, 5.0, 40.0, 55.0, 10.0],
        "disk": [1e5, 2e5, 1.5e5, 3e5, 1e5],
        "disk_r": [1e4, 2e4, 1e4, 3e4, 2e4],
        "swap": [0.0, 0.0, 1.0, 2.0, 1.5],
    }
    assert render_line_chart(values=series["gpu"], title="gpu")
    assert render_multi_chart(series=series, title="all")
    assert "gpu" in ALL_KEYS and "disk" in ALL_KEYS
    pngs = build_chart_pngs(series, which="gpu", host_id="t")
    assert len(pngs) == 1 and pngs[0][1][:8] == b"\x89PNG\r\n\x1a\n"
    disk = build_chart_pngs(series, which="disk", host_id="t")
    assert disk and disk[0][1][:8] == b"\x89PNG\r\n\x1a\n"


def test_gif_from_frames():
    series = {
        "cpu": [float(i) for i in range(20)],
        "mem": [50.0 + i for i in range(20)],
        "net": [100.0 + i * 3 for i in range(20)],
        "gpu": [float(i % 7) for i in range(20)],
    }
    gif = build_rolling_gif(series, which="gpu", host_id="t", window=8, step=2)
    assert gif and gif[:6] in (b"GIF87a", b"GIF89a")
    one = render_line_chart(values=[1, 2, 3], title="x")
    assert frames_to_gif([one]) is None
