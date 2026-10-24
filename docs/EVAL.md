# Offline evaluation

Reproduce Precision / Recall / F1 / FPR for host ML methods on a labeled window dataset.

## Window contract (schema v2)

`build-dataset` stores **raw** metric windows in `.npy` and writes `scaler.json`.
Train and live `predict_window` each apply the scaler **once**. Meta fields:

- `windows_format: "raw"`
- `schema_version: 2`

Legacy datasets without these fields are treated as pre-scaled; rebuild before trusting eval.
Do **not** enable host ML in production until the gate below passes.

## Prepare data

```bash
# example: build windows from CSV collects
python -m sysspectogram build-dataset \
  --normal data/normal.csv --anomaly data/anomaly.csv \
  --out dataset/raw_v4
```

Need `dataset/.../train/{normal,anomaly}/*.npy` and `val/...`.

## Run

```bash
python scripts/eval_offline.py \
  --dataset dataset/ \
  --model artifacts/live \
  --methods fuse,cnn,iforest,zscore \
  --runtime onnx \
  --out reports/eval/
```

Or via CLI:

```bash
python -m sysspectogram eval schema --model artifacts/live
python -m sysspectogram eval stamp-schema --model artifacts/live   # write schema_version=2 if missing
python -m sysspectogram eval run --dataset dataset/ --model artifacts/live --out reports/eval/
```

Writes `reports/eval/metrics.json` and `reports/eval/metrics.md` (includes per-class score mean/std and near-constant warnings). Artifact `meta.json` should carry `schema_version` (and `windows_format: raw`).

### Enablement gate (safety)

Default config stays `runtime.prefer: notorch`. Only flip to `onnx` / `torch_ml` after:

```bash
python scripts/check_ml_ready.py \
  --dataset dataset/raw_v4 \
  --model artifacts/raw_v4 \
  --runtime onnx
```

Gate requires fuse recall ≥ 0.7, fuse FPR **strictly better** than zscore, and no near-constant score warnings.

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

## 2026-10-22 measurement (dataset/raw_v4, artifacts/raw_v4) — schema v2

Rebuilt with raw windows + deeper CNN + label smoothing. Command:

```bash
.venv/bin/python scripts/eval_offline.py \
  --dataset dataset/raw_v4 --model artifacts/raw_v4 \
  --methods fuse,cnn,iforest,zscore --runtime torch_ml \
  --out reports/eval/raw_v4
```

| Method | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: |
| zscore | (see metrics.json) | | | high |
| cnn | 1.0 | 1.0 | 1.0 | 0.0 |
| iforest | 0.0 | 0.0 | 0.0 | 0.0 |
| fuse | 1.0 | 0.8421 | 0.9143 | 0.0 |

CNN separates classes under the fixed contract. IsolationForest alone stays weak at the fuse threshold; fuse is usable. **Default `runtime.prefer` remains `notorch`** — enable only after `check_ml_ready.py` on your own data. Filters make lab CSV separation easier than wild VPS traffic; treat as local builder evidence, not friend-default.

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

