# Offline evaluation

Reproduce Precision / Recall / F1 / FPR for host ML methods on a labeled window dataset.

## Prepare data

```bash
# example: build windows from CSV collects
python -m sysspectogram build-dataset \
  --normal data/normal.csv --anomaly data/anomaly.csv \
  --out dataset/
```

Need `dataset/train/{normal,anomaly}/*.npy` and `dataset/val/{normal,anomaly}/*.npy`.

## Run

```bash
python scripts/eval_offline.py \
  --dataset dataset/ \
  --model artifacts/live \
  --methods fuse,cnn,iforest,zscore \
  --runtime onnx \
  --out reports/eval/
```

Writes `reports/eval/metrics.json` and `reports/eval/metrics.md`.

## Methods

| Method | Meaning |
| --- | --- |
| `fuse` | Configured CNN + Isolation Forest fusion (production path) |
| `cnn` | CNN probability alone |
| `iforest` | Isolation Forest score alone |
| `zscore` | Naive max-\|z\| on tabular features (baseline) |

## Limits

- Synthetic or lab CSV ≠ real APT campaign.
- Threshold comes from training `meta.json` (recall-oriented); FPR is reported explicitly.
- Without a model dir, only `zscore` runs.

## v1.0 measurement (dataset/real, artifacts/real_v3)

Command:

```bash
.venv/bin/python scripts/eval_offline.py --dataset dataset/real --model artifacts/real_v3 --methods fuse,cnn,iforest,zscore --runtime onnx --out reports/eval/v1.0
```

Validation split: 187 windows (139 normal, 48 anomaly). Output: `reports/eval/v1.0/metrics.md`.

| Method | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: |
| zscore | 0.2930 | 0.9583 | 0.4488 | 0.7986 |
| cnn | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| iforest | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| fuse | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

What the numbers mean:

- The model methods never flag a window. The CNN returns 0.0 for normal and anomaly windows alike, and the Isolation Forest score is identical across windows.
- Bypassing the artifact scaler, the CNN returns about 1.0 for almost every window, normal included. So the trained model does not separate these classes under either input convention.
- The windows are already normalized to [0, 1] in the dataset, while `predict_window` applies the artifact scaler again. That is a likely contributor, but it does not explain the lack of separation on its own.
- `zscore` catches 96% of anomalies at 80% FPR, which is not usable as a detector.

Decision needed before the v1.0 release: retrain on `dataset/real` (or a newer labeled set) and re-measure, or ship v1.0 with the model path marked experimental and the fusion thresholds unchanged. No threshold was tuned to make these numbers look better.

Fix made during this run: `scripts/eval_offline.py` passed windows as `(1, T, F)` to `predict_window`, which expects `(T, F)`. The model methods now run.

