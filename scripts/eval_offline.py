#!/usr/bin/env python3
"""Offline evaluation: models + statistical baselines on labeled windows."""

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
        return [], np.asarray([], dtype=np.int32)
    return windows, np.asarray(labels, dtype=np.int32)


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


def _auc_metrics(y: np.ndarray, scores: np.ndarray) -> dict:
    out: dict = {"roc_auc": None, "pr_auc": None, "recall_at_fpr_1pct": None, "recall_at_fpr_5pct": None}
    if y.size < 2 or len(np.unique(y)) < 2:
        return out
    try:
        from sklearn.metrics import (
            average_precision_score,
            roc_auc_score,
            roc_curve,
        )

        out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
        fpr, tpr, _ = roc_curve(y, scores)
        for key, target in (("recall_at_fpr_1pct", 0.01), ("recall_at_fpr_5pct", 0.05)):
            ok = np.where(fpr <= target)[0]
            out[key] = round(float(tpr[ok[-1]]), 4) if ok.size else 0.0
    except Exception:
        pass
    return out


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


def _method_threshold(meta: dict, name: str, default: float = 0.5) -> float:
    thr_map = meta.get("thresholds") if isinstance(meta.get("thresholds"), dict) else {}
    if name in thr_map:
        try:
            return float(thr_map[name])
        except (TypeError, ValueError):
            pass
    if name == "iforest" and meta.get("iforest_threshold") is not None:
        try:
            return float(meta["iforest_threshold"])
        except (TypeError, ValueError):
            pass
    if name == "cnn" and meta.get("cnn_threshold") is not None:
        try:
            return float(meta["cnn_threshold"])
        except (TypeError, ValueError):
            pass
    try:
        return float(meta.get("threshold", default))
    except (TypeError, ValueError):
        return default


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--model", type=Path, default=None, help="artifacts dir for cnn/iforest/fuse")
    ap.add_argument(
        "--methods",
        default="fuse,cnn,iforest,zscore,robust_z,ewma,iforest_stats,pca",
        help="comma list of methods / baselines",
    )
    ap.add_argument("--out", type=Path, default=Path("reports/eval"))
    ap.add_argument("--runtime", default="onnx", help="onnx|torch_ml for model methods")
    ap.add_argument(
        "--split",
        default="test",
        help="eval split: test (preferred) or val",
    )
    ap.add_argument(
        "--gate",
        action="store_true",
        help="exit 1 unless fuse beats best baseline on PR-AUC and recall@FPR1%%",
    )
    args = ap.parse_args()

    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    meta_path = args.dataset / "meta.json"
    windows_format = "scaled"
    ds_meta: dict = {}
    if meta_path.exists():
        ds_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        windows_format = str(ds_meta.get("windows_format") or "scaled").strip().lower()
    if windows_format == "scaled":
        print(
            "error: dataset windows_format=scaled (legacy double-scale risk). "
            "Rebuild with build-dataset (schema v2 raw).",
            file=sys.stderr,
        )
        return 2

    train_w, train_y = _load_split(args.dataset, "train")
    if not train_w:
        raise SystemExit(f"no train windows under {args.dataset}/train")

    eval_split = args.split
    eval_w, y = _load_split(args.dataset, eval_split)
    if not eval_w and eval_split == "test":
        eval_split = "val"
        eval_w, y = _load_split(args.dataset, "val")
    if y.size == 0:
        raise SystemExit(f"empty {eval_split} labels")

    normal_train = [w for w, lab in zip(train_w, train_y) if int(lab) == 0] or train_w

    scaler = None
    scaler_path = args.dataset / "scaler.json"
    if scaler_path.is_file():
        from sysspectogram.preprocess.scaler import WindowScaler

        scaler = WindowScaler.load(scaler_path)

    model_meta: dict = {}
    infer = None
    if any(m in methods for m in ("fuse", "cnn", "iforest")):
        if args.model is None:
            raise SystemExit("--model required for fuse/cnn/iforest")
        from sysspectogram.ml.infer import load_inferencer

        meta_m = args.model / "meta.json"
        if meta_m.is_file():
            try:
                model_meta = json.loads(meta_m.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                model_meta = {}
        try:
            infer = load_inferencer(args.model, runtime=args.runtime)
        except Exception as exc:
            print(f"warning: model load failed ({exc}); model methods skipped", file=sys.stderr)
            methods = [m for m in methods if m not in {"fuse", "cnn", "iforest"}]

    results: dict = {
        "dataset": str(args.dataset),
        "windows_format": windows_format,
        "eval_split": eval_split,
        "n_eval": int(y.size),
        "threshold_source": "val_artifacts_or_normal_quantile",
        "methods": {},
        "baselines": {},
        "score_stats": {},
        "warnings": [],
        "best_baseline": None,
    }

    baseline_names = {"zscore", "robust_z", "ewma", "iforest_stats", "pca"}
    want_base = [m for m in methods if m in baseline_names]
    if want_base:
        from sysspectogram.ml.baselines import BASELINE_FITTERS

        best_name = None
        best_pr = -1.0
        for name in want_base:
            fn = BASELINE_FITTERS.get(name)
            if fn is None:
                continue
            try:
                br = fn(normal_train, eval_w, scaler=scaler)
            except Exception as exc:
                results["warnings"].append(f"{name} failed: {exc}")
                continue
            pred = (br.scores >= br.threshold).astype(np.int32)
            row = {
                "threshold": br.threshold,
                **_metrics(y, pred),
                **_auc_metrics(y, br.scores),
            }
            results["baselines"][name] = row
            results["methods"][name] = row
            results["score_stats"][name] = _score_stats(br.scores, y)
            pr = row.get("pr_auc")
            if pr is not None and float(pr) > best_pr:
                best_pr = float(pr)
                best_name = name
        results["best_baseline"] = best_name

    if infer is not None:
        cnn_s, if_s, fuse_s = [], [], []
        for w in eval_w:
            pred = infer.predict_window(w.reshape(w.shape[-2], w.shape[-1]))
            cnn_s.append(pred.cnn_prob)
            if_s.append(pred.iforest_score)
            fuse_s.append(pred.score)
        cnn_s = np.asarray(cnn_s, dtype=np.float64)
        if_s = np.asarray(if_s, dtype=np.float64)
        fuse_s = np.asarray(fuse_s, dtype=np.float64)
        for name, arr in (("cnn", cnn_s), ("iforest", if_s), ("fuse", fuse_s)):
            results["score_stats"][name] = _score_stats(arr, y)
            if _near_constant(arr):
                msg = f"{name} scores near-constant on {eval_split} (std<{1e-4})"
                results["warnings"].append(msg)
                print(f"warning: {msg}", file=sys.stderr)
            thr = _method_threshold(model_meta, name, float(getattr(infer, "threshold", 0.5)))
            if name in methods:
                results["methods"][name] = {
                    "threshold": thr,
                    "threshold_from": "model_meta",
                    **_metrics(y, (arr >= thr).astype(np.int32)),
                    **_auc_metrics(y, arr),
                }

    args.out.mkdir(parents=True, exist_ok=True)
    out_json = args.out / "metrics.json"
    out_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Offline eval results",
        "",
        f"Dataset: `{args.dataset}` (n={y.size}, split={eval_split}, windows_format={windows_format})",
        f"Best baseline: `{results.get('best_baseline')}`",
        "",
        "| Method | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | R@FPR1% |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, row in results["methods"].items():
        lines.append(
            f"| {name} | {row.get('precision', 0):.4f} | {row.get('recall', 0):.4f} | "
            f"{row.get('f1', 0):.4f} | {row.get('fpr', 0):.4f} | "
            f"{row.get('roc_auc')} | {row.get('pr_auc')} | {row.get('recall_at_fpr_1pct')} |"
        )
    if results["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {w}" for w in results["warnings"])
    (args.out / "metrics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))

    if args.gate:
        return _gate(results)
    return 0


def _gate(results: dict) -> int:
    """Enablement: fuse must beat best baseline on PR-AUC and recall@FPR 1%."""
    fuse = results["methods"].get("fuse")
    if not fuse:
        print("gate fail: need fuse method", file=sys.stderr)
        return 1
    baselines = results.get("baselines") or {
        k: v
        for k, v in results["methods"].items()
        if k in {"zscore", "robust_z", "ewma", "iforest_stats", "pca"}
    }
    if not baselines:
        print("gate fail: no baselines computed", file=sys.stderr)
        return 1
    best_name = results.get("best_baseline")
    best = baselines.get(best_name) if best_name else None
    if best is None:
        best_name, best = max(
            baselines.items(),
            key=lambda kv: (kv[1].get("pr_auc") is not None, kv[1].get("pr_auc") or -1),
        )
        results["best_baseline"] = best_name
    fuse_pr = fuse.get("pr_auc")
    best_pr = best.get("pr_auc")
    fuse_r1 = fuse.get("recall_at_fpr_1pct")
    best_r1 = best.get("recall_at_fpr_1pct")
    if fuse_pr is None or best_pr is None:
        print("gate fail: missing PR-AUC (need both classes in eval split)", file=sys.stderr)
        return 1
    if float(fuse_pr) <= float(best_pr):
        print(
            f"gate fail: fuse PR-AUC {fuse_pr} <= best baseline {best_name} {best_pr}",
            file=sys.stderr,
        )
        return 1
    if fuse_r1 is None or best_r1 is None or float(fuse_r1) < float(best_r1):
        print(
            f"gate fail: fuse recall@FPR1% {fuse_r1} < baseline {best_name} {best_r1}",
            file=sys.stderr,
        )
        return 1
    if results.get("warnings"):
        print("gate fail: score separation warnings present", file=sys.stderr)
        return 1
    print(
        f"gate ok: fuse beats baseline {best_name} (PR-AUC {fuse_pr} > {best_pr})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
