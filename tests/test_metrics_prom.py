from sysspectogram.metrics_prom import PromRegistry


def test_prom_render_contains_gauges():
    reg = PromRegistry()
    reg.set_gauge("sysspectogram_host_score", 0.42, help_text="score")
    reg.inc_counter("sysspectogram_host_alerts_total")
    text = reg.render()
    assert "sysspectogram_up 1" in text
    assert "sysspectogram_host_score 0.42" in text
    assert "sysspectogram_host_alerts_total 1" in text


def test_feed_tail_and_fp(tmp_path, monkeypatch):
    from sysspectogram import feed_tail as ft

    monkeypatch.setattr(ft, "state_root", lambda: tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)
    (reports / "alerts.jsonl").write_text(
        '{"ts": 1, "type": "host_anomaly", "score": 0.9}\n', encoding="utf-8"
    )
    out = ft.feed_tail(limit=10, host_id="web1")
    assert out["ok"] and out["rows"]
    assert out["rows"][0]["host_id"] == "web1"
    fp = ft.record_false_positive(label="host_fp", source="test")
    assert fp["ok"] and fp["n"] == 1
