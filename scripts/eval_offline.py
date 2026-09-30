#!/usr/bin/env python3
"""Offline evaluation: fuse / cnn / iforest / zscore on labeled windows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_split(dataset: Path, split: str) -> tuple[list[np.ndarray], np.ndarray]:
    windows: list[np.ndarray] = []
    labels: list[int] = []
    for label, name in ((0, "normal"), (1, "anomaly")):
        d = dataset / split / name
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.npy")):
            windows.append(np.load(p).astype(np.float32))
            labels.append(label)
    if not windows:
        raise SystemExit(f"no windows under {dataset}/{split}/{{normal,anomaly}}")
    return windows, np.asarray(labels, dtype=np.int32)


def _zscore_fit(windows: list[np.ndarray]) -> tuple[np.ndarray, np.ndarray]:
    from sysspectogram.preprocess.heatmap import tabular_features

    feats = np.vstack([tabular_features(w) for w in windows])
    mu = feats.mean(axis=0)
    sigma = feats.std(axis=0)
    sigma = np.where(sigma < 1e-6, 1.0, sigma)
    return mu, sigma


def _zscore_score(windows: list[np.ndarray], mu: np.ndarray, sigma: np.ndarray) -> np.ndarray:
    from sysspectogram.preprocess.heatmap import tabular_features

    out = []
    for w in windows:
        f = tabular_features(w)
        z = np.abs((f - mu) / sigma)
        out.append(float(np.clip(z.max() / 6.0, 0.0, 1.0)))
    return np.asarray(out, dtype=np.float64)


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--model", type=Path, default=None, help="artifacts dir for cnn/iforest")
    ap.add_argument(
        "--methods",
        default="fuse,cnn,iforest,zscore",
        help="comma list: fuse,cnn,iforest,zscore",
    )
    ap.add_argument("--out", type=Path, default=Path("reports/eval"))
    ap.add_argument("--runtime", default="onnx", help="onnx|torch_ml for model methods")
    args = ap.parse_args()

    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    train_w, train_y = _load_split(args.dataset, "train")
    val_w, y = _load_split(args.dataset, "val")
    if y.size == 0:
        raise SystemExit("empty val labels")

    normal_train = [w for w, lab in zip(train_w, train_y) if int(lab) == 0] or train_w
    mu, sigma = _zscore_fit(normal_train)

    infer = None
    thr = 0.5
    if any(m in methods for m in ("fuse", "cnn", "iforest")):
        if args.model is None:
            raise SystemExit("--model required for fuse/cnn/iforest")
        from sysspectogram.ml.infer import load_inferencer

        try:
            infer = load_inferencer(args.model, runtime=args.runtime)
            thr = float(getattr(infer, "threshold", 0.5))
        except Exception as exc:
            print(f"warning: model load failed ({exc}); model methods skipped", file=sys.stderr)
            methods = [m for m in methods if m == "zscore"]

    results: dict = {"dataset": str(args.dataset), "n_val": int(y.size), "methods": {}}

    if "zscore" in methods:
        scores = _zscore_score(val_w, mu, sigma)
        # threshold: prefer high recall like train pick — use 0.5 default
        z_thr = 0.5
        pred = (scores >= z_thr).astype(np.int32)
        results["methods"]["zscore"] = {"threshold": z_thr, **_metrics(y, pred)}

    if infer is not None:
        cnn_s, if_s, fuse_s = [], [], []
        for w in val_w:
            pred = infer.predict_window(w)
            cnn_s.append(pred.cnn_prob)
            if_s.append(pred.iforest_score)
            fuse_s.append(pred.score)
        cnn_s = np.asarray(cnn_s)
        if_s = np.asarray(if_s)
        fuse_s = np.asarray(fuse_s)
        if "cnn" in methods:
            results["methods"]["cnn"] = {
                "threshold": thr,
                **_metrics(y, (cnn_s >= thr).astype(np.int32)),
            }
        if "iforest" in methods:
            results["methods"]["iforest"] = {
                "threshold": thr,
                **_metrics(y, (if_s >= thr).astype(np.int32)),
            }
        if "fuse" in methods:
            results["methods"]["fuse"] = {
                "threshold": thr,
                **_metrics(y, (fuse_s >= thr).astype(np.int32)),
            }

    args.out.mkdir(parents=True, exist_ok=True)
    out_json = args.out / "metrics.json"
    out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    # markdown table
    lines = [
        "# Offline eval results",
        "",
        f"Dataset: `{args.dataset}` (n_val={y.size})",
        "",
        "| Method | Precision | Recall | F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, row in results["methods"].items():
        lines.append(
            f"| {name} | {row['precision']:.4f} | {row['recall']:.4f} | "
            f"{row['f1']:.4f} | {row['fpr']:.4f} |"
        )
    (args.out / "metrics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
