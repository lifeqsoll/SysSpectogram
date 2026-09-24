from __future__ import annotations

from pathlib import Path

import pandas as pd
from rich.console import Console

from sysspectogram.audit.report import build_report, write_json
from sysspectogram.ml.infer import EnsembleInferencer
from sysspectogram.preprocess.window import dataframe_to_matrix, iter_windows

console = Console()


def run_analyze(
    csv_path: Path,
    artifacts_dir: Path,
    out_path: Path | None = None,
    stride: int = 5,
) -> dict:
    infer = EnsembleInferencer(artifacts_dir)
    df = pd.read_csv(csv_path).fillna(0.0)
    columns = infer.columns or [c for c in df.columns if c != "timestamp"]
    for c in columns:
        if c not in df.columns:
            df[c] = 0.0
    matrix = dataframe_to_matrix(df, columns)
    anomalies = []
    total = 0
    for start, window in iter_windows(matrix, window_size=infer.window_size, stride=stride):
        total += 1
        pred = infer.predict_window(window)
        if pred.is_anomaly:
            anomalies.append(
                {
                    "window_start_row": start,
                    "score": pred.score,
                    "cnn_prob": pred.cnn_prob,
                    "iforest_score": pred.iforest_score,
                }
            )
    report = build_report(anomalies=anomalies)
    report["source_csv"] = str(csv_path)
    report["windows_scanned"] = total
    report["windows_anomaly"] = len(anomalies)
    report["threshold"] = infer.threshold
    if out_path is not None:
        write_json(out_path, report)
        console.print(f"wrote {out_path}")
    console.print(
        f"scanned={total} anomalies={len(anomalies)} "
        f"rate={len(anomalies) / max(total, 1):.2%}"
    )
    return report
