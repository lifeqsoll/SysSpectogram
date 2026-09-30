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
