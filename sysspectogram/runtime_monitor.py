from __future__ import annotations

import time
from collections import deque
from pathlib import Path

from rich.console import Console

from sysspectogram.audit.processes import list_top_processes
from sysspectogram.audit.report import append_jsonl
from sysspectogram.collect.daemon import CollectDaemon
from sysspectogram.collect.metrics import MetricsCollector
from sysspectogram.ml.infer import load_inferencer
from sysspectogram.notify import format_process_lines, notify
from sysspectogram.preprocess.window import rows_to_matrix

console = Console()


def run_monitor(
    artifacts_dir: Path,
    *,
    interval_sec: float = 5.0,
    cooldown_sec: float = 60.0,
    top_processes: int = 3,
    max_cores: int = 16,
    socket_sample_every: int = 5,
    jsonl_out: Path | None = None,
) -> None:
    infer = load_inferencer(artifacts_dir, runtime="onnx" if (artifacts_dir / "cnn.onnx").exists() else "torch_ml")
    columns = infer.columns
    if not columns:
        raise RuntimeError("artifacts meta.json has empty columns; retrain/rebuild dataset")

    collector = MetricsCollector(max_cores=max_cores, socket_sample_every=socket_sample_every)
    buf: deque = deque(maxlen=infer.window_size)
    daemon = CollectDaemon(collector, interval_sec=1.0, buffer_size=None)

    last_alert = 0.0
    last_infer = 0.0
    console.print(
        f"[bold]monitor[/] window={infer.window_size}s interval={interval_sec}s "
        f"threshold={infer.threshold:.3f}"
    )

    def on_sample(row: dict) -> None:
        nonlocal last_alert, last_infer
        slim = {c: float(row.get(c, 0.0)) for c in columns}
        buf.append(slim)
        now = time.monotonic()
        if len(buf) < infer.window_size:
            return
        if now - last_infer < interval_sec:
            return
        last_infer = now
        matrix = rows_to_matrix(list(buf), columns)
        pred = infer.predict_window(matrix)
        status = "ANOMALY" if pred.is_anomaly else "ok"
        console.print(
            f"{status} score={pred.score:.3f} cnn={pred.cnn_prob:.3f} "
            f"iforest={pred.iforest_score:.3f}"
        )
        if not pred.is_anomaly:
            return
        if now - last_alert < cooldown_sec:
            return
        last_alert = now
        tops = list_top_processes(limit=top_processes)
        body = (
            f"score={pred.score:.3f} (thr={pred.threshold:.3f})\n"
            + format_process_lines(tops)
        )
        console.print(f"[red bold]ALERT[/]\n{body}")
        notify("SysSpectogram anomaly", body)
        if jsonl_out is not None:
            append_jsonl(
                jsonl_out,
                {
                    "type": "anomaly",
                    "score": pred.score,
                    "cnn_prob": pred.cnn_prob,
                    "iforest_score": pred.iforest_score,
                    "threshold": pred.threshold,
                    "top_processes": tops,
                },
            )

    daemon.run(duration_sec=None, on_sample=on_sample)
