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
            w = np.load(p).astype(np.float32)
            if w.ndim == 3 and w.shape[0] == 1:
                w = w[0]
            windows.append(w)
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


def _score_stats(scores: np.ndarray, y: np.ndarray) -> dict:
    def _side(mask: np.ndarray) -> dict:
        s = scores[mask]
        if s.size == 0:
            return {"n": 0, "mean": None, "std": None}
        return {
            "n": int(s.size),
            "mean": round(float(s.mean()), 6),
            "std": round(float(s.std()), 6),
        }

    return {"normal": _side(y == 0), "anomaly": _side(y == 1)}


def _near_constant(scores: np.ndarray, eps: float = 1e-4) -> bool:
    return float(np.std(scores)) < eps


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
    ap.add_argument(
        "--gate",
        action="store_true",
        help="exit 1 unless fuse beats zscore on FPR at recall>=0.7 (safety enablement check)",
    )
    args = ap.parse_args()

    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    meta_path = args.dataset / "meta.json"
    windows_format = "scaled"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        windows_format = str(meta.get("windows_format") or "scaled").strip().lower()
        if windows_format == "scaled":
            print(
                "warning: dataset windows_format=scaled (legacy). "
                "Rebuild with build-dataset (schema v2 raw) for honest eval.",
                file=sys.stderr,
            )

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

    results: dict = {
        "dataset": str(args.dataset),
        "windows_format": windows_format,
        "n_val": int(y.size),
        "methods": {},
        "score_stats": {},
        "warnings": [],
    }

    if "zscore" in methods:
        scores = _zscore_score(val_w, mu, sigma)
        z_thr = 0.5
        pred = (scores >= z_thr).astype(np.int32)
        results["methods"]["zscore"] = {"threshold": z_thr, **_metrics(y, pred)}
        results["score_stats"]["zscore"] = _score_stats(scores, y)

    if infer is not None:
        cnn_s, if_s, fuse_s = [], [], []
        for w in val_w:
            # predict_window expects raw (T, F) and applies scaler once.
            pred = infer.predict_window(w.reshape(w.shape[-2], w.shape[-1]))
            cnn_s.append(pred.cnn_prob)
            if_s.append(pred.iforest_score)
            fuse_s.append(pred.score)
        cnn_s = np.asarray(cnn_s)
        if_s = np.asarray(if_s)
        fuse_s = np.asarray(fuse_s)
        for name, arr in (("cnn", cnn_s), ("iforest", if_s), ("fuse", fuse_s)):
            results["score_stats"][name] = _score_stats(arr, y)
            if _near_constant(arr):
                msg = f"{name} scores near-constant on val (std<{1e-4}); model not separating"
                results["warnings"].append(msg)
                print(f"warning: {msg}", file=sys.stderr)
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
    lines = [
        "# Offline eval results",
        "",
        f"Dataset: `{args.dataset}` (n_val={y.size}, windows_format={windows_format})",
        "",
        "| Method | Precision | Recall | F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, row in results["methods"].items():
        lines.append(
            f"| {name} | {row['precision']:.4f} | {row['recall']:.4f} | "
            f"{row['f1']:.4f} | {row['fpr']:.4f} |"
        )
    if results["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {w}" for w in results["warnings"])
    (args.out / "metrics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))

    if args.gate:
        fuse = results["methods"].get("fuse")
        z = results["methods"].get("zscore")
        if not fuse or not z:
            print("gate fail: need fuse and zscore methods", file=sys.stderr)
            return 1
        if fuse["recall"] < 0.7:
            print(f"gate fail: fuse recall {fuse['recall']} < 0.7", file=sys.stderr)
            return 1
        if fuse["fpr"] >= z["fpr"]:
            print(
                f"gate fail: fuse FPR {fuse['fpr']} not better than zscore {z['fpr']}",
                file=sys.stderr,
            )
            return 1
        if results["warnings"]:
            print("gate fail: score separation warnings present", file=sys.stderr)
            return 1
        print("gate ok: fuse usable vs zscore baseline", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
